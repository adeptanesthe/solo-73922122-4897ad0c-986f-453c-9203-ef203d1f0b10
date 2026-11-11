"""gzip 压缩 JSONL 审计文件的流式校验与判定。

文件格式（解压后必须是 UTF-8）：

* 第 1 行只允许一个键：``{"policy": {...}}``；
* 后续每行一个原格式审计事件（fork / chdir / access）；
* 最多 :data:`MAX_EVENTS` 个事件；
* 事件里出现的不同 PID（``pid`` 与 ``child_pid``）最多 :data:`MAX_PIDS` 个；
* 解压后每行最多 :data:`MAX_LINE_BYTES` 字节（不计行尾 ``\\n``）。

处理方式（单遍流式）：

1. 逐行解压、校验并把事件喂给有状态的判定器；轨迹逐条写入磁盘临时文件。
   判定遇首个拒绝即停止，但循环仍继续检查后续每一行的格式/必需字段，并
   读到 gzip 流末尾以验证 CRC/尾部是否完整。
2. 调用方仅在整份文件处理成功后，才从轨迹临时文件分块输出响应。

任何坏行、超限或损坏的压缩流都会在进入响应前抛出
:class:`FileValidationError`，调用方据此返回 422，不泄露核对结果；内存中
只保留各 PID 的当前 cwd（PID 数量受限），不会随事件数增长。
"""

from __future__ import annotations

import gzip
import json
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Iterator

from .engine import (
    EventEvaluator,
    PolicyError,
    normalize_policy,
    policy_summary,
)

MAX_EVENTS = 200_000
MAX_PIDS = 256
MAX_LINE_BYTES = 4096

# JSON 序列化时使用紧凑分隔符，避免无谓地放大磁盘临时文件。
_JSON_KW = {"ensure_ascii": False, "separators": (",", ":")}


class FileValidationError(Exception):
    """上传文件的格式/约束错误；``line`` 为解压后的物理行号（从 1 开始）。"""

    def __init__(
        self,
        line: int | None,
        message: str,
        event_index: int | None = None,
    ) -> None:
        self.line = line
        self.message = message
        self.event_index = event_index
        super().__init__(str(self))

    def __str__(self) -> str:
        if self.line is None:
            return self.message
        if self.event_index is not None:
            return f"第 {self.line} 行（第 {self.event_index} 个事件）：{self.message}"
        return f"第 {self.line} 行：{self.message}"


@dataclass
class EvaluationSummary:
    allowed: bool
    failure_event_seq: int | None
    failure_reason: str | None
    events_total: int
    events_evaluated: int
    policy_effective: dict

    def as_meta(self) -> dict:
        """按原 JSON 响应字段顺序生成流式响应的前缀对象。"""
        return {
            "allowed": self.allowed,
            "failure_event_seq": self.failure_event_seq,
            "failure_reason": self.failure_reason,
            "events_total": self.events_total,
            "events_evaluated": self.events_evaluated,
            "policy_effective": self.policy_effective,
        }


@dataclass
class PreparedInput:
    """一遍流式处理后的产物：事件校验完毕，轨迹已落在磁盘临时文件。"""

    cfg: dict
    trace_path: str
    summary: EvaluationSummary


# --------------------------------------------------------------------------- #
# 第一遍：流式解压 + 逐行校验
# --------------------------------------------------------------------------- #
def _iter_gzip_lines(gz: gzip.GzipFile, max_line_bytes: int) -> Iterator[tuple[int, bytes]]:
    """逐行读取解压内容，返回 (物理行号, 行内容字节)。

    使用带长度上限的 ``readline``，即使遇到超长行也不会先把它整个读进内存。
    """
    line_no = 0
    while True:
        # 多读 2 字节，用于区分“恰好 4KiB + 换行”和“超过 4KiB”。
        raw = gz.readline(max_line_bytes + 2)
        if not raw:
            return
        line_no += 1
        if raw.endswith(b"\r\n"):
            content = raw[:-2]  # Windows 换行不计入行长
        elif raw.endswith(b"\n"):
            content = raw[:-1]
        else:
            content = raw
        if len(content) > max_line_bytes:
            raise FileValidationError(
                line_no, f"行长度超过 {max_line_bytes} 字节（解压后）"
            )
        yield line_no, content


def _decode_json_line(
    content: bytes, line_no: int, event_index: int | None = None
) -> object:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FileValidationError(
            line_no, f"不是合法的 UTF-8：{exc}", event_index
        ) from exc
    if not text.strip():
        raise FileValidationError(line_no, "空行不是合法事件", event_index)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise FileValidationError(
            line_no, f"不是合法 JSON：{exc}", event_index
        ) from exc


def _parse_policy_line(content: bytes) -> dict:
    obj = _decode_json_line(content, 1)
    if not isinstance(obj, dict):
        raise FileValidationError(1, "首行必须是包含 policy 的 JSON 对象")
    if set(obj.keys()) != {"policy"}:
        raise FileValidationError(
            1, '首行只允许包含一个 "policy" 字段，不能同时携带 events 等其它字段'
        )
    try:
        return normalize_policy(obj["policy"])
    except PolicyError as exc:
        raise FileValidationError(1, f"policy 不合法：{exc}") from exc


def _event_payload(
    obj: object, line_no: int, event_index: int
) -> dict:
    """按原接口的字段约定校验事件，返回可交给引擎的紧凑 dict。"""
    if not isinstance(obj, dict):
        raise FileValidationError(line_no, "事件必须是 JSON 对象", event_index)

    etype = obj.get("type")
    if etype not in ("fork", "chdir", "access"):
        raise FileValidationError(
            line_no, f"type 必须是 fork/chdir/access，收到 {etype!r}", event_index
        )

    pid = obj.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise FileValidationError(line_no, "缺少合法的 pid（正整数）", event_index)

    payload: dict = {"type": etype, "pid": pid}

    ppid = obj.get("ppid")
    if ppid is not None:
        if not isinstance(ppid, int) or isinstance(ppid, bool):
            raise FileValidationError(line_no, "ppid 必须是整数", event_index)
        payload["ppid"] = ppid

    child = obj.get("child_pid")
    if child is not None:
        if not isinstance(child, int) or isinstance(child, bool) or child <= 0:
            raise FileValidationError(
                line_no, "child_pid 必须是正整数", event_index
            )
        payload["child_pid"] = child

    operation = obj.get("operation")
    if operation is not None:
        if operation not in ("read", "write", "execute"):
            raise FileValidationError(
                line_no, "operation 必须是 read/write/execute", event_index
            )
        payload["operation"] = operation

    path = obj.get("path")
    if path is not None:
        if not isinstance(path, str):
            raise FileValidationError(line_no, "path 必须是字符串", event_index)
        payload["path"] = path

    if etype == "fork":
        if "child_pid" not in payload:
            raise FileValidationError(
                line_no, "fork 事件缺少合法的 child_pid", event_index
            )
    else:
        if etype == "access" and "operation" not in payload:
            raise FileValidationError(
                line_no, "access 事件缺少 operation", event_index
            )
        if not payload.get("path"):
            raise FileValidationError(
                line_no, f"{etype} 事件缺少非空 path", event_index
            )

    return payload


def _event_pids(payload: dict) -> set[int]:
    pids = {payload["pid"]}
    child = payload.get("child_pid")
    if isinstance(child, int):
        pids.add(child)
    return pids


def prepare_event_file(
    fileobj: BinaryIO,
    trace_path: str,
    *,
    max_events: int | None = None,
    max_pids: int | None = None,
    max_line_bytes: int | None = None,
) -> PreparedInput:
    """一遍流式解压、校验并判定上传内容，轨迹逐条写入 ``trace_path``。

    ``fileobj`` 必须是可读的 gzip 二进制文件对象。判定遇首个拒绝即停止，
    但仍继续逐行校验后续事件的格式/必需字段，并读到 gzip 流末尾验证尾部。
    任何错误都抛出 :class:`FileValidationError`（携带行号），不会返回部分
    核对结果；调用方负责删除已写入的临时轨迹。
    """
    limit_events = MAX_EVENTS if max_events is None else max_events
    limit_pids = MAX_PIDS if max_pids is None else max_pids
    line_limit = MAX_LINE_BYTES if max_line_bytes is None else max_line_bytes

    cfg: dict | None = None
    evaluator: EventEvaluator | None = None
    total = 0
    pids: set[int] = set()
    last_line = 0
    failure: dict | None = None

    try:
        with gzip.GzipFile(fileobj=fileobj, mode="rb") as gz, open(
            trace_path, "w", encoding="utf-8"
        ) as trace:
            for line_no, content in _iter_gzip_lines(gz, line_limit):
                last_line = line_no
                if line_no == 1:
                    cfg = _parse_policy_line(content)
                    evaluator = EventEvaluator(cfg)
                    continue

                event_index = total + 1
                if total >= limit_events:
                    raise FileValidationError(
                        line_no,
                        f"事件数量超过上限 {limit_events}",
                        event_index,
                    )

                payload = _event_payload(
                    _decode_json_line(content, line_no, event_index),
                    line_no,
                    event_index,
                )

                event_pids = _event_pids(payload)
                if not event_pids <= pids:
                    if len(pids | event_pids) > limit_pids:
                        raise FileValidationError(
                            line_no,
                            f"不同 PID 数量超过上限 {limit_pids}",
                            event_index,
                        )
                    pids.update(event_pids)
                total += 1

                # 首个拒绝之后只做格式/字段校验，不再判定，也不写轨迹。
                if failure is not None:
                    continue

                assert evaluator is not None
                try:
                    entry = evaluator.feed(payload, event_index)
                except PolicyError as exc:  # 兜底：语义错误也归到具体行
                    raise FileValidationError(
                        line_no, str(exc), event_index
                    ) from exc
                trace.write(json.dumps(entry, **_JSON_KW))
                trace.write("\n")
                if evaluator.failure is not None:
                    failure = entry
    except FileValidationError:
        raise
    except (gzip.BadGzipFile, zlib.error, EOFError) as exc:
        # 读不到下一行/流尾 CRC 校验失败，都按损坏的压缩流处理。
        raise FileValidationError(
            last_line + 1, f"gzip 压缩流损坏或截断：{exc}"
        ) from exc

    if cfg is None or evaluator is None:
        raise FileValidationError(1, "文件为空，缺少首行 policy")

    summary = EvaluationSummary(
        allowed=failure is None,
        failure_event_seq=None if failure is None else failure["seq"],
        failure_reason=None if failure is None else failure["reason"],
        events_total=total,
        events_evaluated=evaluator.evaluated,
        policy_effective=policy_summary(cfg),
    )
    return PreparedInput(cfg=cfg, trace_path=trace_path, summary=summary)


# --------------------------------------------------------------------------- #
# 响应流
# --------------------------------------------------------------------------- #
def iter_response_parts(meta: dict, trace_path: str) -> Iterator[bytes]:
    """按原 JSON 接口的字段结构，分块输出响应，不整体加载轨迹文件。"""
    prefix = json.dumps(meta, **_JSON_KW)
    # meta 以 "}" 结尾；先去掉右花括号，再追加 trace 数组开头。
    yield (prefix[:-1] + ',"trace":[').encode("utf-8")

    first = True
    with open(trace_path, "r", encoding="utf-8") as trace_fh:
        for line in trace_fh:
            chunk = line.strip()
            if not chunk:
                continue
            if not first:
                yield b","
            first = False
            yield chunk.encode("utf-8")
    yield b"]}"

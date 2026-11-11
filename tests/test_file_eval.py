"""gzip JSONL 上传链路的纯标准库测试。

运行：python3 -I tests/test_file_eval.py
"""

from __future__ import annotations

import gzip
import io
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine import evaluate  # noqa: E402
from app.file_eval import (  # noqa: E402
    FileValidationError,
    iter_response_parts,
    prepare_event_file,
)

POLICY = {
    "ProtectSystem": "full",
    "ProtectHome": "read-only",
    "ReadWritePaths": ["/var/lib/app", "/etc/app"],
    "InaccessiblePaths": ["/etc/secret"],
    "PrivateTmp": True,
    "UnitName": "app.service",
}


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        raise AssertionError(f"用例失败: {name} {detail}")
    print(f"  ok - {name}")


def compact(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def make_gzip(lines: list[bytes], newline_at_end: bool = True) -> bytes:
    raw = b"\n".join(lines)
    if newline_at_end:
        raw += b"\n"
    return gzip.compress(raw, mtime=0)


def policy_lines(events: list, policy=POLICY) -> list[bytes]:
    return [compact({"policy": policy})] + [compact(e) for e in events]


def run_upload(data: bytes, **limits):
    """在临时目录内完成流式处理，并返回解析后的响应。"""
    with tempfile.TemporaryDirectory() as tmp:
        trace_path = os.path.join(tmp, "trace.jsonl")
        prepared = prepare_event_file(io.BytesIO(data), trace_path, **limits)
        body = b"".join(
            iter_response_parts(prepared.summary.as_meta(), trace_path)
        )
        return json.loads(body)


def expect_error(data: bytes, line: int | None, needle: str = "", **limits):
    with tempfile.TemporaryDirectory() as tmp:
        try:
            prepare_event_file(
                io.BytesIO(data), os.path.join(tmp, "trace.jsonl"), **limits
            )
        except FileValidationError as exc:
            check(
                f"报错含行号 {line} / {needle}",
                (line is None or exc.line == line) and (needle in str(exc)),
                str(exc),
            )
            return exc
        raise AssertionError(f"应抛出 FileValidationError（line={line} {needle}）")


def test_valid_fork_and_relative_paths() -> None:
    print("test_valid_fork_and_relative_paths")
    events = [
        {"type": "chdir", "pid": 100, "path": "/var/lib/app"},
        {"type": "fork", "pid": 100, "child_pid": 101, "ppid": 100},
        {"type": "access", "pid": 101, "operation": "write", "path": "state.db"},
        {"type": "access", "pid": 101, "operation": "read", "path": "logs/today.log"},
        {"type": "access", "pid": 100, "operation": "write", "path": "/etc/app/config.ini"},
    ]
    response = run_upload(make_gzip(policy_lines(events)))
    check("全部通过", response["allowed"] is True)
    check("events_total 为全部事件", response["events_total"] == len(events))
    check("events_evaluated 等于总数", response["events_evaluated"] == len(events))
    check("轨迹条数一致", len(response["trace"]) == len(events))
    check("fork 继承 cwd", response["trace"][1]["cwd_after"] == "/var/lib/app")
    check(
        "子进程相对路径解析",
        response["trace"][2]["normalized_path"] == "/var/lib/app/state.db",
    )


def test_trace_matches_json_api() -> None:
    print("test_trace_matches_json_api")
    events = [
        {"type": "chdir", "pid": 1, "path": "/srv/app/work"},
        {"type": "access", "pid": 1, "operation": "write", "path": "/etc/app/x"},
        {"type": "access", "pid": 1, "operation": "write", "path": "/usr/lib/evil.so"},
    ]
    expected = evaluate(POLICY, events)
    actual = run_upload(make_gzip(policy_lines(events)))
    check("与原 JSON 接口结果一致", actual == expected)


def test_stop_but_validate_rest() -> None:
    print("test_stop_but_validate_rest")
    events = [
        {"type": "access", "pid": 100, "operation": "write", "path": "/usr/lib/evil.so"},
        {"type": "access", "pid": 100, "operation": "write", "path": "/tmp/cache/idx"},
        {"type": "access", "pid": 100, "operation": "read", "path": "/etc/secret/key"},
    ]
    response = run_upload(make_gzip(policy_lines(events)))
    check("首个拒绝即停止", response["allowed"] is False)
    check("失败序号为 1", response["failure_event_seq"] == 1)
    check("events_total 仍计全部", response["events_total"] == 3)
    check("events_evaluated 只到首个拒绝", response["events_evaluated"] == 1)
    check("轨迹只含已判定事件", len(response["trace"]) == 1)

    # 首个拒绝之后的坏行也必须被发现（格式/必需字段检查不能随判定停止）。
    bad_after_deny = [
        {"type": "access", "pid": 100, "operation": "write", "path": "/usr/lib/evil.so"},
        {"type": "fork", "pid": 100},  # 缺 child_pid
    ]
    expect_error(make_gzip(policy_lines(bad_after_deny)), 3, "child_pid")


def test_limits() -> None:
    print("test_limits")
    events = [
        {"type": "access", "pid": 1, "operation": "read", "path": "/a"},
        {"type": "access", "pid": 2, "operation": "read", "path": "/b"},
        {"type": "access", "pid": 3, "operation": "read", "path": "/c"},
    ]
    expect_error(make_gzip(policy_lines(events)), 4, "事件数量超过上限 2", max_events=2)
    expect_error(make_gzip(policy_lines(events)), 4, "不同 PID 数量超过上限 2", max_pids=2)
    # child_pid 也是 PID 空间的成员
    fork_events = [
        {"type": "fork", "pid": 1, "child_pid": 2},
        {"type": "fork", "pid": 1, "child_pid": 3},
    ]
    expect_error(make_gzip(policy_lines(fork_events)), 3, "不同 PID 数量超过上限 2", max_pids=2)


def test_bad_lines_and_utf8() -> None:
    print("test_bad_lines_and_utf8")
    expect_error(
        make_gzip([compact({"policy": POLICY}), b"{not json"]),
        2,
        "不是合法 JSON",
    )
    expect_error(
        make_gzip([
            compact({"policy": POLICY}),
            compact({"type": "access", "pid": 1, "operation": "write"}),
        ]),
        2,
        "缺少非空 path",
    )
    expect_error(
        make_gzip([
            compact({"policy": POLICY}),
            compact({"type": "wat", "pid": 1}),
        ]),
        2,
        "type 必须是",
    )
    expect_error(
        make_gzip([
            compact({"policy": POLICY}),
            b'{"type":"access","pid":1,"operation":"read","path":"/x\xff"}' + b"\n",
        ]),
        2,
        "UTF-8",
    )
    expect_error(
        make_gzip([
            compact({"policy": POLICY}),
            b"",
            compact({"type": "access", "pid": 1, "operation": "read", "path": "/x"}),
        ]),
        2,
        "空行",
    )


def test_line_length() -> None:
    print("test_line_length")
    long_path = "/" + "a" * 4200
    expect_error(
        make_gzip([
            compact({"policy": POLICY}),
            compact({"type": "access", "pid": 1, "operation": "read", "path": long_path}),
        ]),
        2,
        "4096",
    )


def test_first_line_and_empty_file() -> None:
    print("test_first_line_and_empty_file")
    expect_error(gzip.compress(b"", mtime=0), 1, "文件为空")
    expect_error(make_gzip([compact({"policy": POLICY, "events": []})]), 1, "policy")
    expect_error(make_gzip([compact({"events": []})]), 1, "policy")
    # 只有 policy、没有事件也是合法的空核对
    response = run_upload(make_gzip([compact({"policy": POLICY})]))
    check("零事件通过", response["allowed"] is True)
    check("零事件总数", response["events_total"] == 0)
    check("零事件轨迹", response["trace"] == [])


def test_corrupt_or_truncated_gzip() -> None:
    print("test_corrupt_or_truncated_gzip")
    good = make_gzip(policy_lines([
        {"type": "access", "pid": 1, "operation": "read", "path": "/x"},
    ]))
    expect_error(good[:-8], None, "损坏或截断")
    expect_error(b"this is not gzip\n", None, "损坏或截断")


def test_docs_sample() -> None:
    print("test_docs_sample")
    sample = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "examples",
        "audit-upload.jsonl.gz",
    )
    with open(sample, "rb") as fh:
        response = run_upload(fh.read())
    check("样例在 fork 后解析相对路径",
          response["trace"][2]["normalized_path"] == "/var/lib/app/state.db")
    check("样例首个拒绝序号", response["failure_event_seq"] == 6)
    check("样例 events_total 为全部 8 个", response["events_total"] == 8)
    check("样例 events_evaluated 为 6", response["events_evaluated"] == 6)


def main() -> int:
    tests = [
        test_valid_fork_and_relative_paths,
        test_trace_matches_json_api,
        test_stop_but_validate_rest,
        test_limits,
        test_bad_lines_and_utf8,
        test_line_length,
        test_first_line_and_empty_file,
        test_corrupt_or_truncated_gzip,
        test_docs_sample,
    ]
    failed = 0
    for test in tests:
        try:
            test()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL - {test.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} 组测试通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

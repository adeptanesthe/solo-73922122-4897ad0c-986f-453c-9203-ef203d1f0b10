"""systemd 沙箱策略判定引擎（仅依赖 Python 标准库）。

判定顺序（与 systemd 挂载语义对齐的简化模型）：

1. 路径规范化：相对路径按进程当前 cwd 拼接，词法解析 ``..`` / ``.``。
2. ``InaccessiblePaths`` 优先判定，命中即拒绝（拒绝路径优先于可写路径，
   即使该路径同时出现在 ReadWritePaths 中也拒绝）。
3. ``PrivateTmp=yes`` 时，``/tmp``、``/var/tmp`` 重映射到私有命名空间，
   私有 tmp 为可写 tmpfs，并在轨迹中标注隔离映射。
4. ``ProtectHome=yes/read-only`` 对 ``/home``、``/root``、``/run/user`` 生效。
5. ``ProtectSystem=full`` 对 ``/usr``、``/boot``、``/efi``、``/etc`` 只读；
   ``strict`` 对除 ``/proc``、``/sys``、``/dev`` 虚拟文件系统外的整个文件系统只读。
6. ``ReadWritePaths`` 可放行第 4、5 步产生的只读阻断，但不能覆盖第 2 步的拒绝。
7. 其余目录默认可写。

引擎以 dict 为输入输出，不依赖 pydantic / fastapi，便于离线单元测试。
"""

from __future__ import annotations

import posixpath
from typing import Any

# systemd 语义中的受保护路径前缀
HOME_PREFIXES = ("/home", "/root", "/run/user")
FULL_PROTECT_PREFIXES = ("/usr", "/boot", "/efi", "/etc")
VIRTUAL_PREFIXES = ("/proc", "/sys", "/dev")
TMP_PREFIXES = ("/tmp", "/var/tmp")

DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_INFO = "info"


class PolicyError(ValueError):
    """策略或事件输入不合法。"""


# --------------------------------------------------------------------------- #
# 路径工具
# --------------------------------------------------------------------------- #
def normalize(path: str) -> str:
    """词法规范化绝对路径（不触碰真实文件系统）。"""
    return posixpath.normpath(path)


def resolve_path(raw: str, cwd: str) -> str:
    """把事件中的绝对/相对路径解析为规范化绝对路径。

    相对路径基于进程当前工作目录 cwd 拼接，``..`` 做词法折叠，
    与进程实际看到的路径解析保持一致（不要求路径真实存在）。
    """
    if not isinstance(raw, str) or not raw:
        raise PolicyError("事件路径必须是非空字符串")
    base = raw if raw.startswith("/") else posixpath.join(cwd or "/", raw)
    return posixpath.normpath(base)


def is_under(path: str, prefix: str) -> bool:
    """组件感知的前缀匹配：``/etc`` 命中 ``/etc/foo`` 但不命中 ``/etcd``。"""
    prefix = prefix.rstrip("/") or "/"
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def matched_prefixes(path: str, prefixes: list[str]) -> list[str]:
    return [p for p in prefixes if is_under(path, p)]


# --------------------------------------------------------------------------- #
# 配置归一化
# --------------------------------------------------------------------------- #
def _first(d: dict, *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in d and d[key] is not None:
            return d[key]
    return default


def _norm_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("yes", "true", "1", "on")
    return bool(value)


def _norm_system(value: Any) -> str:
    v = str(value).strip().lower() if value is not None else "off"
    if v in ("no", "false", "0", "off", ""):
        return "off"
    if v in ("yes", "true", "1", "on"):
        # systemd: ProtectSystem=yes 等价于 full
        return "full"
    if v in ("full", "strict"):
        return v
    raise PolicyError(f"未知的 ProtectSystem 取值: {value!r}")


def _norm_home(value: Any) -> str:
    v = str(value).strip().lower() if value is not None else "off"
    if v in ("no", "false", "0", "off", ""):
        return "off"
    if v in ("yes", "true", "1", "on"):
        return "yes"
    if v in ("read-only", "readonly", "ro"):
        return "read-only"
    if v == "tmpfs":
        # tmpfs 与 yes 一样使原 home 目录不可见
        return "yes"
    raise PolicyError(f"未知的 ProtectHome 取值: {value!r}")


def _norm_path_list(value: Any, directive: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        value = [v for v in value.split() if v]
    if not isinstance(value, list):
        raise PolicyError(f"{directive} 必须是字符串数组")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PolicyError(f"{directive} 中的路径必须是非空字符串")
        p = item.strip()
        if not p.startswith("/"):
            raise PolicyError(f"{directive} 只接受绝对路径，收到相对路径: {p!r}")
        result.append(normalize(p))
    return result


# --------------------------------------------------------------------------- #
# 核心判定
# --------------------------------------------------------------------------- #
def _private_tmp_sandbox_path(host_path: str, unit_name: str) -> tuple[str, str]:
    """返回 (沙箱内路径, 命中的宿主机 tmp 前缀)。"""
    for base in TMP_PREFIXES:
        if is_under(host_path, base):
            suffix = host_path[len(base):]  # "" 或以 "/" 开头
            leaf = "tmp" if base == "/tmp" else "var-tmp"
            sandbox = (
                f"/tmp/systemd-private-{unit_name}/{leaf}{suffix}"
            )
            return sandbox, base
    return "", ""


def check_access(
    host_path: str,
    operation: str,
    cfg: dict,
) -> dict:
    """对一次已规范化的访问做完整策略判定，返回判定明细。"""
    notes: list[str] = []
    matched: list[str] = []
    sandbox_path: str | None = None

    protect_system = cfg["protect_system"]
    protect_home = cfg["protect_home"]
    rw_paths: list[str] = cfg["read_write_paths"]
    inaccessible: list[str] = cfg["inaccessible_paths"]
    private_tmp = cfg["private_tmp"]
    unit_name = cfg["unit_name"]

    # 1) InaccessiblePaths：拒绝优先，对所有操作（含 read/execute/chdir）生效
    deny_hits = matched_prefixes(host_path, inaccessible)
    if deny_hits:
        for p in deny_hits:
            matched.append(f"InaccessiblePaths={p}")
        return {
            "decision": DECISION_DENY,
            "reason": (
                f"路径 {host_path} 命中 InaccessiblePaths（{', '.join(deny_hits)}），"
                "该路径在命名空间内被挂载为空文件/目录，所有操作均被拒绝；"
                "拒绝路径优先于 ReadWritePaths"
            ),
            "matched_policies": matched,
            "notes": notes,
            "sandbox_path": None,
        }

    # 2) PrivateTmp：/tmp 与 /var/tmp 重映射到私有命名空间（可写 tmpfs）
    if private_tmp:
        sandbox_path, tmp_base = _private_tmp_sandbox_path(host_path, unit_name)
        if sandbox_path:
            notes.append(
                f"PrivateTmp=yes：宿主机 {tmp_base} 被私有 tmpfs 遮盖，"
                f"{host_path} 在沙箱内映射为 {sandbox_path}，"
                "与主机及其它服务隔离，且私有 tmp 默认可写"
            )
            matched.append("PrivateTmp=yes")
            return {
                "decision": DECISION_ALLOW,
                "reason": (
                    f"{operation} {host_path} 落入 PrivateTmp 私有命名空间（{sandbox_path}），"
                    "私有 tmp 可写且与主机隔离，放行"
                ),
                "matched_policies": matched,
                "notes": notes,
                "sandbox_path": sandbox_path,
            }

    blocker: str | None = None  # 只读类阻断策略项（可被 ReadWritePaths 放行）

    # 3) ProtectHome
    home_hits = matched_prefixes(host_path, HOME_PREFIXES)
    if home_hits and protect_home == "yes":
        for p in home_hits:
            matched.append(f"ProtectHome=yes (前缀 {p})")
        return {
            "decision": DECISION_DENY,
            "reason": (
                f"路径 {host_path} 位于 home 区域（{', '.join(home_hits)}），"
                "ProtectHome=yes 使其在命名空间内完全不可见，所有操作均被拒绝"
            ),
            "matched_policies": matched,
            "notes": notes,
            "sandbox_path": None,
        }
    if home_hits and protect_home == "read-only" and operation == "write":
        blocker = "ProtectHome=read-only"
        matched.append(f"ProtectHome=read-only (前缀 {home_hits[0]})")

    # 4) ProtectSystem（仅写操作受只读限制；read/execute 不受影响）
    if operation == "write":
        if protect_system == "strict" and not matched_prefixes(host_path, VIRTUAL_PREFIXES):
            blocker = "ProtectSystem=strict"
            matched.append("ProtectSystem=strict (整文件系统只读，/proc /sys /dev 除外)")
        elif protect_system == "full" and matched_prefixes(host_path, FULL_PROTECT_PREFIXES):
            blocker = "ProtectSystem=full"
            hit = matched_prefixes(host_path, FULL_PROTECT_PREFIXES)[0]
            matched.append(f"ProtectSystem=full (前缀 {hit})")

    # 5) ReadWritePaths：放行只读阻断，但不能覆盖 InaccessiblePaths / ProtectHome=yes
    rw_hits = matched_prefixes(host_path, rw_paths)
    if rw_hits:
        for p in rw_hits:
            matched.append(f"ReadWritePaths={p}")
    if blocker:
        if rw_hits:
            notes.append(
                f"{blocker} 原本阻断该写操作，ReadWritePaths（{', '.join(rw_hits)}）"
                "以可写绑定挂载覆盖只读限制，放行"
            )
            return {
                "decision": DECISION_ALLOW,
                "reason": f"ReadWritePaths 覆盖 {blocker}，{host_path} 可写",
                "matched_policies": matched,
                "notes": notes,
                "sandbox_path": None,
            }
        return {
            "decision": DECISION_DENY,
            "reason": (
                f"写操作被 {blocker} 阻断：{host_path} 位于只读区域，"
                "且未被 ReadWritePaths 列为可写"
            ),
            "matched_policies": matched,
            "notes": notes,
            "sandbox_path": None,
        }

    # 6) 默认放行（其余目录默认可写；只读策略不限制 read/execute）
    if rw_hits:
        notes.append(
            f"路径命中 ReadWritePaths（{', '.join(rw_hits)}），"
            f"当前操作为 {operation}，默认即允许"
        )
    return {
        "decision": DECISION_ALLOW,
        "reason": f"无策略阻断 {operation} {host_path}，默认放行",
        "matched_policies": matched,
        "notes": notes,
        "sandbox_path": None,
    }


# --------------------------------------------------------------------------- #
# 事件流评估
# --------------------------------------------------------------------------- #
def normalize_policy(policy: dict) -> dict:
    """把请求中的策略归一化为引擎内部 cfg；非法配置抛 PolicyError。"""
    if not isinstance(policy, dict):
        raise PolicyError("policy 必须是 JSON 对象")
    return {
        "protect_system": _norm_system(_first(policy, "ProtectSystem", "protect_system")),
        "protect_home": _norm_home(_first(policy, "ProtectHome", "protect_home")),
        "read_write_paths": _norm_path_list(
            _first(policy, "ReadWritePaths", "read_write_paths", default=[]),
            "ReadWritePaths",
        ),
        "inaccessible_paths": _norm_path_list(
            _first(policy, "InaccessiblePaths", "inaccessible_paths", default=[]),
            "InaccessiblePaths",
        ),
        "private_tmp": _norm_bool(_first(policy, "PrivateTmp", "private_tmp", default=False)),
        "unit_name": str(_first(policy, "unit_name", "UnitName", default="daemon.service")),
    }


def policy_summary(cfg: dict) -> dict:
    """公开的策略回显，供流式接口复用。"""
    return _policy_summary(cfg)


def _base_trace(event: dict, seq: int, cwd_before: str) -> dict:
    return {
        "seq": event.get("seq", seq),
        "event_type": event.get("type"),
        "pid": event.get("pid"),
        "ppid": event.get("ppid"),
        "operation": event.get("operation"),
        "raw_path": event.get("path"),
        "cwd_before": cwd_before,
        "cwd_after": cwd_before,
        "normalized_path": None,
        "sandbox_path": None,
        "decision": DECISION_INFO,
        "reason": "",
        "matched_policies": [],
        "notes": [],
    }


class EventEvaluator:
    """有状态的流式事件判定器。

    只保存每个 PID 的当前工作目录（调用方需保证 PID 数量有界）；
    每次 ``feed`` 处理一个事件并返回对应轨迹条目，不累积历史轨迹，
    因此内存占用不随事件总数增长。
    """

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.cwd_table: dict[int, str] = {}
        self.evaluated = 0
        self.failure: dict | None = None

    def feed(self, event: dict, seq: int) -> dict:
        """处理一个事件；遇首个拒绝时记录到 ``self.failure`` 并返回该轨迹。"""
        if not isinstance(event, dict):
            raise PolicyError(f"第 {seq} 个事件必须是 JSON 对象")
        etype = event.get("type")
        pid = event.get("pid")
        if not isinstance(pid, int) or pid <= 0:
            raise PolicyError(f"第 {seq} 个事件缺少合法的 pid")
        cwd_before = self.cwd_table.get(pid, "/")
        entry = _base_trace(event, seq, cwd_before)
        self.evaluated += 1

        # -- fork：子进程继承父进程 cwd -----------------------------------
        if etype == "fork":
            child = event.get("child_pid")
            if not isinstance(child, int) or child <= 0:
                raise PolicyError(f"第 {seq} 个 fork 事件缺少合法的 child_pid")
            self.cwd_table[child] = cwd_before
            entry["cwd_after"] = cwd_before
            entry["decision"] = DECISION_INFO
            entry["reason"] = (
                f"进程 {pid} 派生子进程 {child}，子进程继承工作目录 {cwd_before}"
            )
            entry["notes"].append("fork 不触发文件访问策略判定，仅传递 cwd 状态")
            return entry

        if etype not in ("chdir", "access"):
            raise PolicyError(
                f"第 {seq} 个事件 type 必须是 fork/chdir/access，收到 {etype!r}"
            )
        raw_path = event.get("path")
        host_path = resolve_path(raw_path if isinstance(raw_path, str) else "", cwd_before)
        entry["normalized_path"] = host_path

        # -- chdir：需要目录的搜索（execute）权限，成功后更新 cwd ----------
        if etype == "chdir":
            result = check_access(host_path, "execute", self.cfg)
            entry["sandbox_path"] = result["sandbox_path"]
            entry["matched_policies"] = result["matched_policies"]
            entry["notes"] = result["notes"]
            if result["decision"] == DECISION_DENY:
                entry["decision"] = DECISION_DENY
                entry["reason"] = f"切换工作目录被拒绝：{result['reason']}"
                self.failure = entry
                return entry
            self.cwd_table[pid] = host_path
            entry["cwd_after"] = host_path
            entry["decision"] = DECISION_ALLOW
            entry["reason"] = (
                f"chdir 解析：{raw_path!r}（相对 {cwd_before}）-> {host_path}，"
                "目录可搜索，工作目录已更新"
            )
            return entry

        # -- access：read / write / execute -------------------------------
        operation = event.get("operation")
        if operation not in ("read", "write", "execute"):
            raise PolicyError(
                f"第 {seq} 个 access 事件的 operation 必须是 read/write/execute"
            )
        result = check_access(host_path, operation, self.cfg)
        entry["sandbox_path"] = result["sandbox_path"]
        entry["matched_policies"] = result["matched_policies"]
        entry["notes"] = result["notes"]
        entry["decision"] = result["decision"]
        entry["reason"] = result["reason"]
        entry["cwd_after"] = cwd_before
        if result["decision"] == DECISION_DENY:
            self.failure = entry
        return entry


def evaluate(policy: dict, events: list[dict]) -> dict:
    """按时间顺序回放审计事件，逐步判定，遇首个失败即停止。

    返回 ``allowed``、``failure_reason``、完整 ``trace`` 与命中的策略项。
    """
    if not isinstance(policy, dict):
        raise PolicyError("policy 必须是 JSON 对象")
    if not isinstance(events, list):
        raise PolicyError("events 必须是数组")
    cfg = normalize_policy(policy)

    evaluator = EventEvaluator(cfg)
    trace: list[dict] = []
    total = len(events)

    for idx, event in enumerate(events, start=1):
        entry = evaluator.feed(event, idx)
        trace.append(entry)
        if evaluator.failure is not None:
            return _fail_response(cfg, trace, entry, total)

    return {
        "allowed": True,
        "failure_event_seq": None,
        "failure_reason": None,
        "events_total": total,
        "events_evaluated": evaluator.evaluated,
        "policy_effective": _policy_summary(cfg),
        "trace": trace,
    }



def _fail_response(cfg: dict, trace: list[dict], entry: dict, total: int) -> dict:
    return {
        "allowed": False,
        "failure_event_seq": entry["seq"],
        "failure_reason": entry["reason"],
        "events_total": total,
        "events_evaluated": len(trace),
        "policy_effective": _policy_summary(cfg),
        "trace": trace,
    }


def _policy_summary(cfg: dict) -> dict:
    return {
        "ProtectSystem": cfg["protect_system"],
        "ProtectHome": cfg["protect_home"],
        "ReadWritePaths": cfg["read_write_paths"],
        "InaccessiblePaths": cfg["inaccessible_paths"],
        "PrivateTmp": cfg["private_tmp"],
        "unit_name": cfg["unit_name"],
    }

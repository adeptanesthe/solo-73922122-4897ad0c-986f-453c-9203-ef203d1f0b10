"""引擎判定测试：纯标准库，直接 `python3 -I tests/test_engine.py` 运行。"""

from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine import evaluate, resolve_path, is_under, PolicyError  # noqa: E402


POLICY = {
    "ProtectSystem": "full",
    "ProtectHome": "read-only",
    "ReadWritePaths": ["/etc/app", "/var/lib/app", "/srv/app/work"],
    "InaccessiblePaths": ["/etc/secret", "/root"],
    "PrivateTmp": "yes",
    "UnitName": "app.service",
}


def check(name: str, cond: bool, detail: str = "") -> None:
    if not cond:
        raise AssertionError(f"用例失败: {name} {detail}")
    print(f"  ok - {name}")


def test_path_utils() -> None:
    print("test_path_utils")
    check("相对路径基于 cwd 拼接", resolve_path("../etc/x", "/var/lib/app") == "/var/lib/etc/x")
    check("点路径规范化", resolve_path("./a/./b", "/srv") == "/srv/a/b")
    check("绝对路径直接规范化", resolve_path("/etc/./app/../passwd", "/") == "/etc/passwd")
    check("越界折叠到根", resolve_path("../../etc", "/tmp") == "/etc")
    check("组件前缀匹配 1", is_under("/etc/app/conf", "/etc"))
    check("组件前缀匹配 2", not is_under("/etcd", "/etc"))
    check("根前缀匹配全部", is_under("/anything", "/"))


def test_allows_and_rwp_override() -> None:
    print("test_allows_and_rwp_override")
    result = evaluate(POLICY, [
        {"type": "access", "pid": 1, "operation": "read", "path": "/usr/bin/app"},
        {"type": "access", "pid": 1, "operation": "write", "path": "/var/lib/app/state.db"},
        {"type": "access", "pid": 1, "operation": "write", "path": "/etc/app/config.ini"},
        {"type": "access", "pid": 1, "operation": "read", "path": "/etc/passwd"},
    ])
    check("全部放行", result["allowed"] is True)
    check("RWP 命中记录",
          any("ReadWritePaths=/etc/app" in p for p in result["trace"][2]["matched_policies"]))
    check("RWP 覆盖说明", any("覆盖" in n for n in result["trace"][2]["notes"]))


def test_protect_system_full_deny() -> None:
    print("test_protect_system_full_deny")
    result = evaluate(POLICY, [
        {"type": "access", "pid": 1, "operation": "write", "path": "/etc/passwd"},
    ])
    check("写 /etc 被拒", result["allowed"] is False)
    check("失败序号=1", result["failure_event_seq"] == 1)
    check("命中 ProtectSystem",
          any("ProtectSystem=full" in p for p in result["trace"][0]["matched_policies"]))
    check("只评估了一个事件", result["events_evaluated"] == 1)


def test_inaccessible_overrides_rwp() -> None:
    print("test_inaccessible_overrides_rwp")
    policy = dict(POLICY)
    policy["ReadWritePaths"] = ["/etc/secret", "/root"]
    result = evaluate(policy, [
        {"type": "access", "pid": 1, "operation": "write", "path": "/etc/secret/key.pem"},
    ])
    check("拒绝优先于可写", result["allowed"] is False)
    check("命中 InaccessiblePaths",
          any("InaccessiblePaths=/etc/secret" in p
              for p in result["trace"][0]["matched_policies"]))


def test_protect_home_modes() -> None:
    print("test_protect_home_modes")
    ro = evaluate(POLICY, [
        {"type": "access", "pid": 1, "operation": "write", "path": "/home/app/f"},
    ])
    check("read-only 下写 home 被拒", ro["allowed"] is False)
    check("命中 ProtectHome",
          any("ProtectHome=read-only" in p for p in ro["trace"][0]["matched_policies"]))

    reads = evaluate(POLICY, [
        {"type": "access", "pid": 1, "operation": "read", "path": "/home/app/f"},
    ])
    check("read-only 下读 home 放行", reads["allowed"] is True)

    policy_yes = dict(POLICY)
    policy_yes["ProtectHome"] = "yes"
    invisible = evaluate(policy_yes, [
        {"type": "access", "pid": 1, "operation": "read", "path": "/home/app/.profile"},
    ])
    check("ProtectHome=yes 读也被拒", invisible["allowed"] is False)
    check("不可见原因", "不可见" in invisible["failure_reason"])

    root_denied = evaluate(policy_yes, [
        {"type": "access", "pid": 1, "operation": "read", "path": "/root/.ssh/id_rsa"},
    ])
    check("/root 被 InaccessiblePaths 优先拦截（拒绝优先）",
          any("InaccessiblePaths=/root" in p
              for p in root_denied["trace"][0]["matched_policies"]))


def test_private_tmp() -> None:
    print("test_private_tmp")
    result = evaluate(POLICY, [
        {"type": "access", "pid": 1, "operation": "write", "path": "/tmp/cache/1.bin"},
        {"type": "access", "pid": 1, "operation": "read", "path": "/var/tmp/x"},
    ])
    check("私有 tmp 写放行", result["allowed"] is True)
    entry = result["trace"][0]
    check("标注沙箱路径",
          entry["sandbox_path"] == "/tmp/systemd-private-app.service/tmp/cache/1.bin")
    check("隔离说明", any("私有 tmpfs" in n for n in entry["notes"]))
    check("命中 PrivateTmp 策略项", "PrivateTmp=yes" in entry["matched_policies"])

    no_tmp = evaluate({**POLICY, "PrivateTmp": False}, [
        {"type": "access", "pid": 1, "operation": "write", "path": "/tmp/f"},
    ])
    check("未启用 PrivateTmp 时 /tmp 默认可写且无映射",
          no_tmp["allowed"] and no_tmp["trace"][0]["sandbox_path"] is None)


def test_fork_inherits_cwd_and_relative_paths() -> None:
    print("test_fork_inherits_cwd_and_relative_paths")
    result = evaluate(POLICY, [
        {"type": "chdir", "pid": 1, "path": "/srv/app/work"},
        {"type": "fork", "pid": 1, "child_pid": 2, "ppid": 1},
        {"type": "access", "pid": 2, "operation": "write", "path": "data/out.log"},
        {"type": "chdir", "pid": 2, "path": "../work2"},
        {"type": "access", "pid": 2, "operation": "write", "path": "x"},
    ])
    check("继承 cwd 后相对路径放行", result["allowed"] is True,
          result.get("failure_reason") or "")
    t3 = result["trace"][2]
    check("相对路径规范化", t3["normalized_path"] == "/srv/app/work/data/out.log")
    t4 = result["trace"][3]
    check("chdir 后 cwd 更新", t4["cwd_after"] == "/srv/app/work2")
    t5 = result["trace"][4]
    check("新 cwd 下相对写解析", t5["normalized_path"] == "/srv/app/work2/x")
    check("work2 不在 RWP 但默认目录可写", result["allowed"] is True)


def test_relative_write_into_protected_area() -> None:
    print("test_relative_write_into_protected_area")
    result = evaluate(POLICY, [
        {"type": "chdir", "pid": 1, "path": "/usr/local"},
        {"type": "access", "pid": 1, "operation": "write", "path": "../lib/evil.so"},
    ])
    check("相对路径规范化后命中保护", result["allowed"] is False)
    check("解析为 /usr/lib", result["trace"][1]["normalized_path"] == "/usr/lib/evil.so")
    check("失败原因含 ProtectSystem", "ProtectSystem" in result["failure_reason"])


def test_strict_mode() -> None:
    print("test_strict_mode")
    policy = {
        "ProtectSystem": "strict",
        "ProtectHome": "off",
        "ReadWritePaths": ["/var/lib/app"],
        "InaccessiblePaths": [],
        "PrivateTmp": False,
    }
    denied = evaluate(policy, [
        {"type": "access", "pid": 1, "operation": "write", "path": "/opt/app/run.pid"},
    ])
    check("strict 下普通目录写被拒", denied["allowed"] is False)
    allowed = evaluate(policy, [
        {"type": "access", "pid": 1, "operation": "write", "path": "/var/lib/app/x"},
        {"type": "access", "pid": 1, "operation": "read", "path": "/opt/app/run.pid"},
        {"type": "access", "pid": 1, "operation": "execute", "path": "/usr/bin/true"},
    ])
    check("RWP 放行 / 读执行不受只读影响", allowed["allowed"] is True)


def test_chdir_into_inaccessible() -> None:
    print("test_chdir_into_inaccessible")
    result = evaluate(POLICY, [
        {"type": "chdir", "pid": 1, "path": "/etc/secret"},
    ])
    check("chdir 进不可访问目录被拒", result["allowed"] is False)
    check("失败在 chdir 事件", result["failure_event_seq"] == 1)


def test_validation_errors() -> None:
    print("test_validation_errors")
    for bad in (
        {"policy": {"ReadWritePaths": ["relative/path"]}, "events": []},
        {"policy": {}, "events": [{"type": "wat", "pid": 1}]},
        {"policy": {}, "events": [{"type": "fork", "pid": 1}]},
        {"policy": {}, "events": [{"type": "access", "pid": 1, "operation": "write"}]},
    ):
        try:
            evaluate(bad["policy"], bad["events"])
        except PolicyError:
            continue
        raise AssertionError(f"应抛出 PolicyError: {bad}")
    print("  ok - 非法输入均被拒绝")


def main() -> int:
    tests = [
        test_path_utils,
        test_allows_and_rwp_override,
        test_protect_system_full_deny,
        test_inaccessible_overrides_rwp,
        test_protect_home_modes,
        test_private_tmp,
        test_fork_inherits_cwd_and_relative_paths,
        test_relative_write_into_protected_area,
        test_strict_mode,
        test_chdir_into_inaccessible,
        test_validation_errors,
    ]
    failed = 0
    for t in tests:
        try:
            t()
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL - {t.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} 组测试通过")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())

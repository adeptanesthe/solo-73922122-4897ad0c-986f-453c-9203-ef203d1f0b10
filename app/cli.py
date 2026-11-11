"""命令行离线入口：不依赖 FastAPI，直接读取请求 JSON 并输出判定结果。

用法：
    python3 -I -m app.cli examples/request.json
    python3 -I -m app.cli examples/request.json --fail-on-deny   # 被阻断时退出码 1
"""

from __future__ import annotations

import argparse
import json
import os
import sys

if __package__ in (None, ""):
    # 直接以脚本方式运行（如 python3 -I /path/to/app/cli.py）时补好包路径
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.engine import PolicyError, evaluate  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="systemd 沙箱策略离线核查（读取 /api/v1/evaluate 同构的请求 JSON）"
    )
    parser.add_argument("request_file", help="包含 policy 与 events 的 JSON 文件，- 表示标准输入")
    parser.add_argument(
        "--fail-on-deny",
        action="store_true",
        help="审计事件被策略阻断时以退出码 1 结束，便于接入巡检脚本",
    )
    args = parser.parse_args(argv)

    if args.request_file == "-":
        payload = json.load(sys.stdin)
    else:
        with open(args.request_file, encoding="utf-8") as fh:
            payload = json.load(fh)

    try:
        result = evaluate(payload.get("policy", {}), payload.get("events", []))
    except PolicyError as exc:
        print(f"输入错误: {exc}", file=sys.stderr)
        return 2

    json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")
    if not result["allowed"]:
        print(
            f"\n[阻断] 事件 #{result['failure_event_seq']}: {result['failure_reason']}",
            file=sys.stderr,
        )
        return 1 if args.fail_on_deny else 0
    print("\n[通过] 全部审计事件均未被沙箱策略阻断", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

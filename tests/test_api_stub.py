"""离线环境下用最小 stub 验证 schemas/main 的字段别名与端点接线。

不替代真实 pydantic/FastAPI 行为，只保证：
1. 模块可导入、端点函数存在；
2. 别名（ProtectSystem 等）与 snake_case 都能进入引擎；
3. 引擎经端点返回的结构符合响应模型约定；
4. 引擎 PolicyError 会被转成 422。

运行：python3 -I tests/test_api_stub.py
"""

from __future__ import annotations

import os
import sys
import types
import typing  # noqa: F401  (Literal 在真实环境/本 stub 下均由标准库提供)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --------------------------------------------------------------------------- #
# pydantic stub
# --------------------------------------------------------------------------- #
class _FieldInfo:
    def __init__(self, default=None, alias=None, description=None, **kw):
        self.default = default
        self.alias = alias
        self.description = description


def Field(default=None, alias=None, description=None, **kw):  # noqa: N802
    return _FieldInfo(default, alias, description)


class _BaseModel:
    def __init__(self, **data):
        for name, finfo in type(self).__fields__.items():
            key = finfo.alias if finfo.alias in data else name
            if key not in data:
                value = finfo.default() if callable(finfo.default) else finfo.default
            else:
                value = data[key]
            setattr(self, name, value)
        for validator in type(self).__validators__:
            for field_name in validator.__field_names__:
                setattr(self, field_name, validator(self, getattr(self, field_name)))

    def model_dump(self, by_alias=False, exclude_none=False):
        out = {}
        for name, finfo in type(self).__fields__.items():
            value = getattr(self, name)
            key = finfo.alias if by_alias and finfo.alias else name
            if exclude_none and value is None:
                continue
            out[key] = value
        return out


def field_validator(*names):  # noqa: N802
    def deco(fn):
        fn.__field_names__ = names
        return fn
    return deco


def ConfigDict(**kw):  # noqa: N802
    return dict(kw)


def _collect_fields(cls):
    fields = {}
    validators = []
    for klass in reversed(cls.__mro__):
        for name, value in vars(klass).items():
            if isinstance(value, _FieldInfo):
                fields[name] = value
            if callable(value) and hasattr(value, "__field_names__"):
                validators.append(value)
        # 裸注解（无 Field() 默认值）在真实 pydantic 中也是必填字段
        for name in getattr(klass, "__annotations__", {}):
            if name not in fields and not callable(getattr(klass, name, None)):
                fields.setdefault(name, _FieldInfo(default=None))
    cls.__fields__ = fields
    cls.__validators__ = validators


_BaseModel.__init_subclass__ = classmethod(lambda cls, *a, **k: _collect_fields(cls))

pydantic = types.ModuleType("pydantic")
pydantic.BaseModel = _BaseModel
pydantic.Field = Field
pydantic.field_validator = field_validator
pydantic.ConfigDict = ConfigDict
sys.modules["pydantic"] = pydantic


# --------------------------------------------------------------------------- #
# fastapi stub
# --------------------------------------------------------------------------- #
class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail


class _Route:
    def __init__(self, path, method, fn):
        self.path = path
        self.method = method
        self.fn = fn


class _FastAPI:
    def __init__(self, **kw):
        self.title = kw.get("title")
        self.routes = []

    def get(self, path, **kw):
        def deco(fn):
            self.routes.append(_Route(path, "GET", fn))
            return fn
        return deco

    def post(self, path, **kw):
        def deco(fn):
            self.routes.append(_Route(path, "POST", fn))
            return fn
        return deco


fastapi = types.ModuleType("fastapi")
fastapi.FastAPI = _FastAPI
fastapi.HTTPException = HTTPException
sys.modules["fastapi"] = fastapi

responses = types.ModuleType("fastapi.responses")


class RedirectResponse:
    def __init__(self, url):
        self.url = url


responses.RedirectResponse = RedirectResponse
sys.modules["fastapi.responses"] = responses


# --------------------------------------------------------------------------- #
# 真实导入被测模块
# --------------------------------------------------------------------------- #
from app.schemas import (  # noqa: E402
    EvaluateRequest,
    PolicyInput,
    AuditEventInput,
    EvaluateResponse,
    TraceEntry,
    EffectivePolicy,
)
from app.main import app, evaluate_events  # noqa: E402
from fastapi import HTTPException as RealHTTPException  # noqa: E402


def _to_response(result: dict) -> EvaluateResponse:
    """stub 不做 pydantic 的递归模型构造，这里手动把 dict 转成响应对象。"""
    data = dict(result)
    data["trace"] = [TraceEntry(**t) for t in result["trace"]]
    data["policy_effective"] = EffectivePolicy(**result["policy_effective"])
    return EvaluateResponse(**data)


def evaluate(req: EvaluateRequest) -> EvaluateResponse:
    from app.engine import evaluate as engine_evaluate
    result = engine_evaluate(
        req.policy.model_dump(by_alias=False, exclude_none=False),
        [e.to_engine() for e in req.events],
    )
    return _to_response(result)

failures = []


def check(name, cond, detail=""):
    if not cond:
        failures.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")
    else:
        print(f"  ok - {name}")


print("test_app_wiring")
paths = {(r.method, r.path) for r in app.routes}
check("注册了评估端点", ("POST", "/api/v1/evaluate") in paths)
check("注册了健康检查", ("GET", "/health") in paths)
check("根路径重定向已注册", ("GET", "/") in paths)

print("test_alias_ingest")
req = EvaluateRequest(
    policy=PolicyInput(
        ProtectSystem="strict",
        ProtectHome="yes",
        ReadWritePaths=["/var/lib/app"],
        InaccessiblePaths=["/etc/secret"],
        PrivateTmp=True,
        UnitName="svc.service",
    ),
    events=[
        AuditEventInput(type="chdir", pid=1, path="/var/lib/app"),
        AuditEventInput(type="fork", pid=1, child_pid=2),
        AuditEventInput(type="access", pid=2, operation="write", path="x"),
        AuditEventInput(type="access", pid=1, operation="write", path="/etc/secret/k"),
    ],
)
resp = evaluate(req)
check("返回 allowed 字段", hasattr(resp, "allowed"))
check("末事件被 InaccessiblePaths 拒绝", resp.allowed is False)
check("失败序号为 4", resp.failure_event_seq == 4)
check("轨迹长度为 4", len(resp.trace) == 4)
check("fork 轨迹标注继承", "继承" in resp.trace[1].reason)
check("chdir 更新 cwd", resp.trace[0].cwd_after == "/var/lib/app")
check("子进程相对路径基于继承 cwd",
      resp.trace[2].normalized_path == "/var/lib/app/x")
check("命中策略项含拒绝路径",
      any("InaccessiblePaths=/etc/secret" in p for p in resp.trace[3].matched_policies))
check("生效策略回显", resp.policy_effective.ProtectSystem == "strict")

print("test_snake_case_ingest")
req2 = EvaluateRequest(
    policy=PolicyInput(protect_system="full", private_tmp=False),
    events=[AuditEventInput(type="access", pid=1, operation="write", path="/etc/x")],
)
resp2 = evaluate(req2)
check("snake_case 入参生效", resp2.allowed is False)
check("full 阻断 /etc 写", "ProtectSystem" in resp2.failure_reason)

print("test_private_tmp_through_api")
req3 = EvaluateRequest(
    policy=PolicyInput(protect_system="strict", **{"PrivateTmp": True}),
    events=[AuditEventInput(type="access", pid=1, operation="write", path="/tmp/a/b")],
)
resp3 = evaluate(req3)
check("strict 下私有 tmp 仍可写", resp3.allowed is True)
check("沙箱映射标注",
      resp3.trace[0].sandbox_path == "/tmp/systemd-private-daemon.service/tmp/a/b")

print("test_policy_error_to_422")
bad = EvaluateRequest(
    policy=PolicyInput(),
    events=[AuditEventInput(type="fork", pid=1)],  # 缺 child_pid
)
try:
    evaluate_events(bad)
    check("缺 child_pid 报 422", False, "未抛异常")
except RealHTTPException as exc:
    check("缺 child_pid 报 422", exc.status_code == 422)

print()
if failures:
    print(f"{len(failures)} 项失败")
    sys.exit(1)
print("全部 stub 接线测试通过")

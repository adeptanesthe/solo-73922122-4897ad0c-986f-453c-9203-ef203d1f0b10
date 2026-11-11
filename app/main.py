"""FastAPI 应用：systemd 沙箱策略离线核查。

所有计算均在本地完成，不发起任何外部网络请求，适合离线维护终端部署。
"""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.responses import RedirectResponse

from . import __version__
from .engine import PolicyError, evaluate
from .schemas import EvaluateRequest, EvaluateResponse

app = FastAPI(
    title="systemd 沙箱策略核查 API",
    version=__version__,
    description=(
        "离线核对 systemd 沙箱指令（ProtectSystem / ProtectHome / ReadWritePaths / "
        "InaccessiblePaths / PrivateTmp）是否会阻断守护进程的真实文件操作。"
        "提交 unit 策略 JSON 与按时间排列的进程审计事件，返回首个失败原因、"
        "完整判定轨迹与命中的策略项，辅助维护人员修改 unit。"
    ),
)


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", tags=["meta"], summary="健康检查")
def health() -> dict:
    return {"status": "ok", "service": "systemd-sandbox-checker", "version": __version__}


@app.post(
    "/api/v1/evaluate",
    response_model=EvaluateResponse,
    tags=["evaluate"],
    summary="回放审计事件并核对沙箱策略",
    responses={
        422: {"description": "策略或事件字段不合法（含相对路径出现在策略中等）"},
    },
)
def evaluate_events(req: EvaluateRequest) -> EvaluateResponse:
    """按进程继承与路径规范化逐步判定；拒绝路径优先于可写路径。"""
    try:
        result = evaluate(
            req.policy.model_dump(by_alias=False, exclude_none=False),
            [e.to_engine() for e in req.events],
        )
    except PolicyError as exc:
        # 引擎侧的语义校验错误统一转 422
        from fastapi import HTTPException

        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return EvaluateResponse(**result)

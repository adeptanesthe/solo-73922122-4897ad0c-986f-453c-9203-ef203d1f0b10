"""FastAPI 应用：systemd 沙箱策略离线核查。

所有计算均在本地完成，不发起任何外部网络请求，适合离线维护终端部署。
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import RedirectResponse, StreamingResponse

from . import __version__
from .engine import PolicyError, evaluate
from .file_eval import (
    FileValidationError,
    iter_response_parts,
    prepare_event_file,
)
from .schemas import EvaluateRequest, EvaluateResponse

try:  # Starlette 随 FastAPI 安装；缺失时仍由响应生成器的 finally 兜底清理。
    from starlette.background import BackgroundTask
except Exception:  # pragma: no cover - 仅用于极简依赖环境
    BackgroundTask = None  # type: ignore[assignment]

try:
    from fastapi.staticfiles import StaticFiles
except Exception:  # pragma: no cover - 仅用于无 FastAPI 的接线测试
    StaticFiles = None  # type: ignore[assignment]

EXAMPLES_DIR = Path(__file__).resolve().parent.parent / "examples"

app = FastAPI(
    title="systemd 沙箱策略核查 API",
    version=__version__,
    description=(
        "离线核对 systemd 沙箱指令（ProtectSystem / ProtectHome / ReadWritePaths / "
        "InaccessiblePaths / PrivateTmp）是否会阻断守护进程的真实文件操作。"
        "提交 unit 策略 JSON 与按时间排列的进程审计事件，返回首个失败原因、"
        "完整判定轨迹与命中的策略项，辅助维护人员修改 unit。\n\n"
        "**文件上传样例（相对本页面的路径）**："
        "[下载 gzip JSONL 样例](examples/audit-upload.jsonl.gz)"
        "（包含 chdir、fork 及子进程相对路径访问），"
        "然后在 `POST /api/v1/evaluate/file` 中上传即可核对。"
    ),
)

if StaticFiles is not None and EXAMPLES_DIR.is_dir():
    # /docs 页面里的相对链接 examples/audit-upload.jsonl.gz 会解析到这里；
    # 同时保留 /docs/examples/... 路径，便于直接按文档目录访问样例。
    app.mount("/examples", StaticFiles(directory=str(EXAMPLES_DIR)), name="examples")
    app.mount(
        "/docs/examples",
        StaticFiles(directory=str(EXAMPLES_DIR)),
        name="docs-examples",
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
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return EvaluateResponse(**result)


# --------------------------------------------------------------------------- #
# gzip JSONL 文件上传
# --------------------------------------------------------------------------- #
def _temp_root() -> str | None:
    """可选的临时目录根；不可用时退回系统默认临时目录。"""
    configured = os.environ.get("SANDBOX_CHECKER_TMPDIR")
    if not configured:
        return None
    try:
        os.makedirs(configured, exist_ok=True)
    except OSError:
        return None
    return configured if os.access(configured, os.W_OK) else None


def _make_cleanup(temp_dir: str):
    """返回幂等清理函数：正常下载结束、断连、失败都只会真正删除一次。"""
    done = False

    def cleanup() -> None:
        nonlocal done
        if done:
            return
        done = True
        shutil.rmtree(temp_dir, ignore_errors=True)

    return cleanup


async def _stream_json(
    meta: dict, trace_path: str, cleanup
) -> AsyncIterator[bytes]:
    try:
        for part in iter_response_parts(meta, trace_path):
            yield part
    finally:
        # 客户端断连或下载结束时 Starlette 会关闭异步生成器，这里必然执行。
        cleanup()


def _evaluate_upload(
    file: UploadFile,
):
    """校验 gzip JSONL 并完成流式判定，返回 (meta, trace_path, cleanup)。"""
    temp_dir = tempfile.mkdtemp(prefix="sandbox-checker-", dir=_temp_root())
    cleanup = _make_cleanup(temp_dir)
    try:
        try:
            file.file.seek(0)
        except Exception as exc:  # 上传中断/文件已关闭
            raise FileValidationError(None, f"无法读取上传文件：{exc}") from exc

        trace_path = os.path.join(temp_dir, "trace.jsonl")

        prepared = prepare_event_file(file.file, trace_path)
        return prepared.summary.as_meta(), prepared.trace_path, cleanup
    except FileValidationError:
        cleanup()
        raise
    except Exception:
        cleanup()
        raise


@app.post(
    "/api/v1/evaluate/file",
    tags=["evaluate"],
    summary="上传 gzip 压缩的 UTF-8 JSONL 文件并核对",
    responses={
        422: {
            "description": (
                "坏行（错误详情包含解压后的行号）、超出事件/PID/行长度限制，"
                "或 gzip 压缩流损坏/截断；此时不返回核对结果"
            )
        },
    },
)
@app.post(
    "/api/v1/evaluate/gzip",
    include_in_schema=False,
    tags=["evaluate"],
)
@app.post(
    "/api/v1/evaluate/upload",
    include_in_schema=False,
    tags=["evaluate"],
)
def evaluate_file(
    file: UploadFile = File(
        ...,
        description=(
            "gzip 压缩的 UTF-8 JSONL：首行仅含 policy，后续每行一个原格式事件；"
            "最多 20 万事件、256 个不同 PID、每行最多 4 KiB"
        ),
    )
):
    """流式解压、校验与判定，响应与原 /api/v1/evaluate 字段和轨迹结构一致。

    整个 gzip（包括首个拒绝之后的行）都会先被校验并读到流尾；任何坏行或
    损坏的压缩流都会在返回结果前转为 422。轨迹只写入磁盘临时文件，
    不整体载入内存。
    """
    try:
        meta, trace_path, cleanup = _evaluate_upload(file)
    except FileValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    kwargs = {}
    if BackgroundTask is not None:
        kwargs["background"] = BackgroundTask(cleanup)
    return StreamingResponse(
        _stream_json(meta, trace_path, cleanup),
        media_type="application/json",
        **kwargs,
    )


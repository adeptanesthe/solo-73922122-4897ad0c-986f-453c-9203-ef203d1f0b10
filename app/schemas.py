"""HTTP 层的请求/响应模型（pydantic v2）。

字段同时接受 systemd 原生写法（``ProtectSystem``）与 snake_case 写法，
策略内的路径强制要求绝对路径，相对路径只允许出现在审计事件里。
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PolicyInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    protect_system: Literal["off", "full", "strict", "yes", "no"] = Field(
        default="off",
        alias="ProtectSystem",
        description="off/no=不启用；full 或 yes=保护 /usr /boot /efi /etc；strict=整文件系统只读",
    )
    protect_home: Literal["off", "yes", "read-only", "no", "tmpfs"] = Field(
        default="off",
        alias="ProtectHome",
        description="off/no=不启用；yes=home 完全不可见；read-only=只读",
    )
    read_write_paths: list[str] = Field(
        default_factory=list,
        alias="ReadWritePaths",
        description="可写路径白名单（绝对路径），可覆盖只读策略，但不能覆盖 InaccessiblePaths",
    )
    inaccessible_paths: list[str] = Field(
        default_factory=list,
        alias="InaccessiblePaths",
        description="不可访问路径（绝对路径），拒绝优先级最高",
    )
    private_tmp: bool = Field(
        default=False,
        alias="PrivateTmp",
        description="yes 时 /tmp、/var/tmp 重映射到私有命名空间",
    )
    unit_name: str = Field(
        default="daemon.service",
        alias="UnitName",
        description="unit 名称，用于标注 PrivateTmp 私有目录",
    )

    @field_validator("read_write_paths", "inaccessible_paths")
    @classmethod
    def _must_be_absolute(cls, value: list[str], info) -> list[str]:
        for p in value:
            if not isinstance(p, str) or not p.strip():
                raise ValueError(f"{info.field_name} 中的路径必须是非空字符串")
            if not p.strip().startswith("/"):
                raise ValueError(
                    f"{info.field_name} 只接受绝对路径，收到相对路径: {p!r}；"
                    "相对路径只能出现在审计事件中"
                )
        return value


class AuditEventInput(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    type: Literal["fork", "chdir", "access"] = Field(description="事件类型")
    pid: int = Field(gt=0, description="发起事件的进程 PID")
    ppid: Optional[int] = Field(default=None, description="父进程 PID（可选，仅用于展示）")
    child_pid: Optional[int] = Field(default=None, gt=0, description="fork 事件的子进程 PID")
    operation: Optional[Literal["read", "write", "execute"]] = Field(
        default=None, description="access 事件的操作类型"
    )
    path: Optional[str] = Field(
        default=None, description="chdir/access 的目标路径，可为绝对路径或相对 cwd 的相对路径"
    )

    def to_engine(self) -> dict:
        return self.model_dump(exclude_none=True)


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    policy: PolicyInput = Field(description="systemd unit 沙箱策略")
    events: list[AuditEventInput] = Field(
        default_factory=list, description="按时间顺序排列的进程审计事件"
    )


class TraceEntry(BaseModel):
    seq: int
    event_type: Optional[str] = None
    pid: Optional[int] = None
    ppid: Optional[int] = None
    operation: Optional[str] = None
    raw_path: Optional[str] = None
    cwd_before: Optional[str] = None
    cwd_after: Optional[str] = None
    normalized_path: Optional[str] = None
    sandbox_path: Optional[str] = None
    decision: str
    reason: str
    matched_policies: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class EffectivePolicy(BaseModel):
    ProtectSystem: str
    ProtectHome: str
    ReadWritePaths: list[str]
    InaccessiblePaths: list[str]
    PrivateTmp: bool
    unit_name: str


class EvaluateResponse(BaseModel):
    allowed: bool = Field(description="全部事件是否均未被沙箱阻断")
    failure_event_seq: Optional[int] = Field(
        default=None, description="首个失败事件序号（从 1 开始），全部通过时为 null"
    )
    failure_reason: Optional[str] = Field(default=None, description="首个失败原因")
    events_total: int
    events_evaluated: int = Field(description="实际评估的事件数；遇首个失败即停止")
    policy_effective: EffectivePolicy = Field(description="归一化后实际生效的策略")
    trace: list[TraceEntry] = Field(description="逐事件的完整判定轨迹")

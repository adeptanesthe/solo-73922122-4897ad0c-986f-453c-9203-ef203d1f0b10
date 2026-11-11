# systemd 沙箱策略离线核查服务

面向 Linux 服务维护人员的**纯离线**工具：给定一个 systemd unit 的沙箱策略 JSON，
以及按时间排列的进程审计事件（派生、切换工作目录、读写/执行绝对或相对路径），
逐步回放并判断守护进程的真实操作会不会被沙箱阻断，输出**首个失败原因、完整判定轨迹
和每一步命中的策略项**，直接指导 unit 修改。

判定引擎（`app/engine.py`）只依赖 Python 标准库；FastAPI 仅用于提供 HTTP 与 `/docs`。
服务运行期不发起任何外部网络请求。

## 支持的策略项

| 策略 | 取值 | 判定语义 |
| --- | --- | --- |
| `ProtectSystem` | `off` / `full` / `strict`（`yes` 等同 `full`） | `full`：`/usr` `/boot` `/efi` `/etc` 只读；`strict`：除 `/proc` `/sys` `/dev` 外整文件系统只读；只限制写 |
| `ProtectHome` | `off` / `yes` / `read-only` | `yes`：`/home` `/root` `/run/user` 完全不可见（所有操作拒绝）；`read-only`：仅拒绝写 |
| `ReadWritePaths` | 绝对路径数组 | 可写白名单，以绑定挂载覆盖上面两项的只读限制 |
| `InaccessiblePaths` | 绝对路径数组 | 命名空间内挂载为空文件/目录，**拒绝优先级最高**，即使同路径在 `ReadWritePaths` 中也拒绝 |
| `PrivateTmp` | `true`/`false` | `/tmp`、`/var/tmp` 重映射到私有 tmpfs，可写且与主机隔离，轨迹中标注沙箱内路径 |

### 判定顺序（每一步轨迹都可对照）

1. **路径规范化**：相对路径按进程当前 cwd 拼接，词法折叠 `.`/`..`（不访问真实文件系统）。
2. **进程继承**：`fork` 事件让子进程继承父进程 cwd；`chdir` 需要目录可搜索（execute），成功后更新该 PID 的 cwd。
3. **InaccessiblePaths 优先**：命中即拒绝，且优先于一切可写放行。
4. **PrivateTmp**：命中 `/tmp`、`/var/tmp` 时标注私有命名空间映射并放行。
5. **ProtectHome**：`yes` 全拒绝；`read-only` 仅写拒绝。
6. **ProtectSystem**：对其余目录的写操作生效（`full` 限定前缀，`strict` 覆盖全局）。
7. **ReadWritePaths 放行**：可覆盖第 5、6 步的只读阻断，不能覆盖第 3 步。
8. 其余目录默认可写；`read`/`execute` 不受只读策略限制。

遇到首个拒绝事件即停止评估，`events_evaluated` 标明实际判定到第几个事件。

## 目录结构

```
app/
  engine.py    # 纯标准库判定引擎（路径规范化、cwd 继承、策略匹配）
  schemas.py   # pydantic v2 请求/响应模型（兼容 systemd 原生字段名与 snake_case）
  main.py      # FastAPI 应用：/docs、/health、/api/v1/evaluate
  cli.py       # 离线命令行入口（无需 FastAPI）
tests/
  test_engine.py   # 引擎测试，python3 -I 直接运行
  test_api_stub.py # 无 FastAPI 环境下的 API 接线测试（内置最小 stub）
examples/request.json
Dockerfile
docker-compose.yml
requirements.txt
```

## 方式一：Docker Compose（推荐，含 /docs）

```bash
docker compose up --build -d
# 交互式文档（可直接在页面上发请求）
xdg-open http://localhost:8080/docs      # Linux 桌面
# 健康检查
curl -s http://localhost:8080/health
# 命令行调用
curl -s -X POST http://localhost:8080/api/v1/evaluate \
  -H 'Content-Type: application/json' \
  --data @examples/request.json | jq .
```

容器以非 root 运行，带 `read_only` 根文件系统、`no-new-privileges`、drop 全部 capabilities，
自身就是一个加固过的沙箱化服务。端口冲突时修改 `docker-compose.yml` 左侧端口即可。

## 方式二：本地 Python 运行

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080
# 打开 http://127.0.0.1:8080/docs
```

## 方式三：完全离线 CLI（不需要安装任何依赖）

引擎与 CLI 仅用标准库，把整个目录拷到无网络的维护机即可：

```bash
# 被阻断时退出码 1，输入非法退出码 2，全通过退出码 0
python3 -I app/cli.py examples/request.json --fail-on-deny
# 也支持标准输入
cat examples/request.json | python3 -I app/cli.py -
```

## 请求格式

策略字段同时接受 systemd 原生写法（`ProtectSystem`）和 snake_case（`protect_system`）。
策略中的路径必须是绝对路径；相对路径只允许出现在审计事件中（相对当前 cwd 解析）。

```json
{
  "policy": {
    "ProtectSystem": "full",
    "ProtectHome": "read-only",
    "ReadWritePaths": ["/etc/app", "/var/lib/app"],
    "InaccessiblePaths": ["/etc/secret"],
    "PrivateTmp": true,
    "UnitName": "app.service"
  },
  "events": [
    {"type": "chdir",  "pid": 100, "path": "/var/lib/app"},
    {"type": "fork",   "pid": 100, "child_pid": 101, "ppid": 100},
    {"type": "access", "pid": 101, "operation": "write", "path": "state.db"},
    {"type": "access", "pid": 100, "operation": "write", "path": "/tmp/cache/idx"},
    {"type": "access", "pid": 100, "operation": "write", "path": "/etc/app/config.ini"},
    {"type": "chdir",  "pid": 100, "path": "/usr/local"},
    {"type": "access", "pid": 100, "operation": "write", "path": "../lib/evil.so"}
  ]
}
```

事件说明：

- `fork`：必须带 `child_pid`，子进程继承父进程当前 cwd，不做文件访问判定。
- `chdir`：带 `path`（绝对或相对），按目录搜索权限判定，成功后更新该 PID 的 cwd。
- `access`：必须带 `operation`（`read`/`write`/`execute`）与 `path`。

## 响应解读（节选）

```json
{
  "allowed": false,
  "failure_event_seq": 7,
  "failure_reason": "写操作被 ProtectSystem=full 阻断：/usr/lib/evil.so 位于只读区域，且未被 ReadWritePaths 列为可写",
  "events_total": 7,
  "events_evaluated": 7,
  "policy_effective": { "...": "归一化后实际生效的策略回显" },
  "trace": [
    {
      "seq": 4,
      "event_type": "access",
      "raw_path": "/tmp/cache/idx",
      "cwd_before": "/var/lib/app",
      "normalized_path": "/tmp/cache/idx",
      "sandbox_path": "/tmp/systemd-private-app.service/tmp/cache/idx",
      "decision": "allow",
      "reason": "write /tmp/cache/idx 落入 PrivateTmp 私有命名空间……",
      "matched_policies": ["PrivateTmp=yes"],
      "notes": ["PrivateTmp=yes：宿主机 /tmp 被私有 tmpfs 遮盖……"]
    }
  ]
}
```

维护动作建议直接来自轨迹：

- 出现 `ProtectSystem`/`ProtectHome` 只读阻断 → 把目标路径加入 unit 的 `ReadWritePaths=`。
- 出现 `InaccessiblePaths` 拒绝 → 从该指令移除对应前缀（`ReadWritePaths` 无法覆盖它）。
- 出现 `ProtectHome=yes` 不可见 → 改为 `ProtectHome=read-only` 或调整程序不再访问 home。
- `sandbox_path` 非空 → 程序看到的是私有 tmp，不能用它与主机或其它服务交换文件。

## 测试

```bash
python3 -I tests/test_engine.py     # 11 组引擎语义测试，无需第三方依赖
python3 -I tests/test_api_stub.py   # 无 FastAPI 环境下的端点/别名/422 接线测试
```

## 建模边界（与真实 systemd 的差异）

- 路径为**词法规范化**，不解析符号链接；systemd 的路径单元也是基于词法前缀匹配，行为基本一致。
- 不建模 UID/GID、DAC 权限、`BindPaths`、`TemporaryFileSystem` 等本工具输入之外的指令。
- `ProtectSystem=strict` 下 `/proc`、`/sys`、`/dev` 视为虚拟文件系统例外；`PrivateTmp` 优先于 strict 判定。
- 不建模挂载传播顺序中 `InaccessiblePaths` 与 `ReadWritePaths` 的复杂叠加，统一按"拒绝优先"处理（这也是 systemd 文档对冲突指令的保守建议）。

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
  engine.py    # 纯标准库判定引擎（路径规范化、cwd 继承、策略匹配、流式判定器）
  file_eval.py # gzip JSONL 流式校验/判定/响应（临时文件，不整体载入内存）
  schemas.py   # pydantic v2 请求/响应模型（兼容 systemd 原生字段名与 snake_case）
  main.py      # FastAPI 应用：/docs、/health、/api/v1/evaluate、文件上传
  cli.py       # 离线命令行入口（无需 FastAPI）
tests/
  test_engine.py    # 引擎测试，python3 -I 直接运行
  test_file_eval.py # gzip 上传链路的格式/限制/停止语义/损坏流测试
  test_api_stub.py  # 无 FastAPI 环境下的 API 接线与流式响应测试
examples/
  request.json          # 原 JSON 接口样例
  audit-upload.jsonl    # 文件接口的可读 JSONL 样例（fork 后相对路径）
  audit-upload.jsonl.gz # /docs 页面通过相对路径提供的 gzip 上传样例
Dockerfile
docker-compose.yml
requirements.txt
```

## 方式一：Docker Compose（推荐，含 /docs）

```bash
docker compose up --build -d
# 交互式文档（可直接在页面上发请求；页面内提供相对路径的上传样例）
xdg-open http://localhost:8080/docs      # Linux 桌面
# 健康检查
curl -s http://localhost:8080/health
# 命令行调用原 JSON 接口
curl -s -X POST http://localhost:8080/api/v1/evaluate \
  -H 'Content-Type: application/json' \
  --data @examples/request.json | jq .
# 命令行演示 gzip 文件核对（样例见 /docs 页面）
curl -s -X POST http://localhost:8080/api/v1/evaluate/file \
  -F 'file=@examples/audit-upload.jsonl.gz' | jq .
```

文件上传样例在 /docs 页面以相对路径 `examples/audit-upload.jsonl.gz` 提供，
直接点击即可下载；容器内的临时轨迹写入 `/tmp`（Compose 中为可写卷），
根文件系统仍保持只读。样例含 `chdir`、`fork` 后的相对路径访问，并在第 6 个
事件被 `ProtectSystem=full` 拒绝；因此演示结果应为
`allowed=false`、`failure_event_seq=6`、`events_total=8`、`events_evaluated=6`，
而第 7、8 个事件虽不再判定，仍会完成格式与 gzip 尾部校验。

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

## gzip 文件上传接口

整日审计事件较多时，不必把所有事件塞进一个 JSON 请求体。两个 POST 端点
（`/api/v1/evaluate/file` 为主，`/api/v1/evaluate/gzip`、`/api/v1/evaluate/upload`
为等价别名）接受 multipart 文件字段 `file`：

```bash
curl -s -X POST http://localhost:8080/api/v1/evaluate/file \
  -F 'file=@examples/audit-upload.jsonl.gz' | jq .
```

文件为 **gzip 压缩的 UTF-8 JSONL**，上传时不需要先解压：

- 解压后的**第 1 行**只允许包含 `policy`：`{"policy": {...}}`，不能再带 `events`；
- 后续**每行一个**与原 JSON 接口相同格式的事件（`fork` / `chdir` / `access`）；
- 最多 **200000 个事件**；
- 事件中出现的不同 PID（`pid` 与 `child_pid`）最多 **256 个**；
- 解压后**每行最多 4096 字节**（不计行尾换行）。

判定仍沿用原策略与 cwd 继承语义：相对路径按进程当前 cwd 拼接，`fork` 子进程
继承父进程 cwd，遇**首个拒绝即停止判定**。响应字段与轨迹结构与原接口完全一致：

- `events_total` 统计文件中的**全部**事件；
- `events_evaluated` / `trace` 只到首个拒绝（含该事件）为止；
- 停止判定后仍会继续检查**后续每一行**的 JSON 格式与必需字段，并读完整个
  gzip 流验证尾部（CRC/截断）。

错误处理：坏行、超出限制、不是合法 UTF-8、gzip 损坏或截断都会返回 **422**，
`detail` 中给出解压后的**物理行号**（首行 policy 为第 1 行），此时**不返回**
任何核对结果。例如：

```json
{"detail": "第 3 行（第 2 个事件）：fork 事件缺少合法的 child_pid"}
```

资源与清理：上传、解压、判定和响应全程**不把文件、事件列表或轨迹整体放入
内存**，内存占用不随事件数增长；判定轨迹写入本请求专属的磁盘临时文件，
响应按轨迹文件分块输出。上传中断、处理失败、下载完成或客户端断连时，
都会删除该请求的临时目录。容器场景可用 `SANDBOX_CHECKER_TMPDIR` 指定临时根目录。

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
python3 -I tests/test_file_eval.py  # gzip 校验/限制/停止后尾部检查/损坏流测试
python3 -I tests/test_api_stub.py   # 无 FastAPI 环境下的端点/别名/422/流式响应接线测试
```

## 建模边界（与真实 systemd 的差异）

- 路径为**词法规范化**，不解析符号链接；systemd 的路径单元也是基于词法前缀匹配，行为基本一致。
- 不建模 UID/GID、DAC 权限、`BindPaths`、`TemporaryFileSystem` 等本工具输入之外的指令。
- `ProtectSystem=strict` 下 `/proc`、`/sys`、`/dev` 视为虚拟文件系统例外；`PrivateTmp` 优先于 strict 判定。
- 不建模挂载传播顺序中 `InaccessiblePaths` 与 `ReadWritePaths` 的复杂叠加，统一按"拒绝优先"处理（这也是 systemd 文档对冲突指令的保守建议）。

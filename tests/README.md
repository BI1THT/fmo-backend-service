# SAS 测试说明

## 运行

```bash
# 单元测试（默认，< 2 秒，无网络、无固定端口、不写 ~/.sas）
dotnet test tests/Sas.Tests/Sas.Tests.csproj

# 只跑单元测试，排除会启动 HttpListener 的集成测试
dotnet test tests/Sas.Tests/Sas.Tests.csproj --filter "Category!=Integration"

# 只跑集成测试
dotnet test tests/Sas.Tests/Sas.Tests.csproj --filter "Category=Integration"
```

测试使用 xUnit v3。生产程序集通过 `InternalsVisibleTo("Sas.Tests")` 暴露内部类型。

## 结构

| 目录 | 覆盖内容 |
|---|---|
| `Certs/` | Base64Url、Ed25519、Root/Intermediate/User 证书、Root/Intermediate CRL 的解析、CBOR 编码与验签 |
| `Trust/` | `CertVerifier` 校验顺序与边界、`RootCaStore` 加载/播种、`CrlManager` 缓存与刷新 |
| `Auth/` | 呼号白名单、proof 签名、ACL、归档上下文、EMQX 模板、完整鉴权管线（21 个拒绝分支） |
| `Logging/` | 日志转义/截断、归档分目录/轮转/保留期/并发 |
| `Server/` | 全局限流与单呼号熔断、`HttpServer` 进程内端到端 |
| `Cli/` | `ConfigParser` 参数解析、版本解析、配置校验 |

## 测试夹具

- `TestPki`：用真实 Ed25519 密钥生成完整的 Root → Intermediate → User 证书链，并构造符合协议 12 元 CBOR 的 proof 签名。
- `AuthTestEnvironment`：组合真实 `RootCaStore`、`AclStore`、`AuthArchive` 和 `HttpAuthHandler`，只替换时钟、随机数和吊销策略。
- `FixedTimeProvider`：可控时钟，用于限流窗口、熔断时长、证书过期与 timestamp 漂移。
- `TempDirectory`：所有 IO 都在系统临时目录内，测试结束清理。

## 覆盖率

`src/Sas.csproj` 在非 Release 配置下生成 portable PDB，便于 `dotnet-coverage` 或 coverlet 采集。
CI 使用 `dotnet-coverage`（xUnit v3 是独立进程，VSTest 数据收集器无法附加），门禁口径为：

- 排除 `Program`（进程入口、更新命令）与 `Sas.Config`（交互式初始化向导、管理员/集群交互命令）；
- 其余代码行覆盖率 ≥ 75%（当前约 86%）：
  - `Sas.certs` 98%、`Sas.Auth` 90%、`Sas.Server` 84%、`Sas.Trust` 81%、`Sas.Cli` 78%、`Sas.Logging` 76%。

本地采集：

```bash
dotnet tool install dotnet-coverage --tool-path ./.tools
./.tools/dotnet-coverage collect "dotnet test tests/Sas.Tests/Sas.Tests.csproj --no-build" \
  -f cobertura -o coverage.xml
```

## 已修复的已知行为

以下历史行为已修复，测试已同步更新：

1. **Root CA 过期与 `pathLen`**：`CertVerifier` 现在检查 `root.exp` 和 `root.pathLen`，分别返回 `RootExpired` / `RootPathLenInvalid`。
2. **长度口径**：`PayloadLength` / `PasswordLength` 统一按 UTF-8 字节计数。
3. **日志截断**：`LogSafe.Format` 输出严格不超过 `maxLength`，且不会拆开代理对。
4. **`crlNumber`**：严格限定为 `uint32`，负值或越界直接拒绝，不再回绕。
5. **CRL 可观测性与 strict**：新增 `NotConfigured` / `NotFetched` / `NotPublished` / `Fresh` / `Stale` / `FetchFailed` 状态；`crl.mode=strict` 时 CRL 不可用即拒绝。
6. **`Base64Url.Decode`**：严格校验字符集与长度，拒绝空白、padding 和标准 base64 字符。
7. **内置角色**：以嵌入 JSON 为单一事实来源，代码兜底与 JSON 保持一致。
8. **归档记录降级**：超限时按 summary → minimal → core 逐级降级，始终输出合法 JSON。

已修复并移除的其他条目：

- 角色判定与协议文档不一致（现为"服务器自身 UID + 指纹 → super；`admins[]` → admin/自定义角色；其他 → user"）。
- `pathLen` 未参与证书解析（Root 缺失时默认 1，Intermediate 缺失时默认 0，越界值报错）。

## 已澄清的行为（不作为缺陷处理）

1. **呼号 `/` 与归档目录 `_`**：合法呼号字符集为 `A-Z 0-9 / -`，不含 `_`，因此 `/` → `_` 不会产生目录冲突；归档记录中的 `callsign` 保留原始呼号。
2. **非 `/auth` 路径返回 404**：`HttpListener` 只注册 `/auth/` 前缀，其他路径由监听器直接返回 404；只有 `/auth` 端点内的失败返回 `{"result":"deny"}`。
3. **归档单条超限不轮转**：单条记录不可拆分；当单条记录大于 `maxFileBytes` 时，文件可能超出上限一条记录的大小，下一条记录会写入新文件。


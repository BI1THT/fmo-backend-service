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

## 已知行为（测试按现状锁定，待单独修复）

以下行为已由测试固定，修复时需同步更新用例名称带 `CurrentBehavior` 的测试：

1. **角色判定与协议文档 §12.1 不一致**：代码中"指纹命中 `admins[]`"返回 `admin`（或自定义角色），文档写的是 `super`；`admins` 为空时服务器自身 UID 返回 `super`。
2. **Root CA 过期不校验**：`RootCaStore` 与 `CertVerifier` 都不检查 `root.exp`。
3. **Intermediate/Root 证书的 `pathLen` 被 `FromJson` 丢弃**：`IntermediateCaCert.FromJson` 不读取 `extensions.pathLen`，导致 `pathLen != 0` 的证书 TBS 与签名不一致，最终表现为 `no trusted root`；`CertVerifier` 中的 `pathLen` 检查在 HTTP 路径上不可达。
4. **`Realm`/`PayloadLength` 以 UTF-16 字符计数**，而协议描述为长度（字节）。
5. **`LogSafe.Format` 最大输出 `maxLength + 1`**（达到上限后追加 `…`）。
6. **`CrlNumber` 由 `long` 强转 `uint`**，负值会回绕成 42 亿。
7. **CRL fail-open**：完全无法获取 CRL 时仍放行（文档只规定了"过期且刷新失败放行"）。
8. **呼号允许 `/`，归档目录将其替换为 `_`**，目录名与呼号不完全一致。
9. **非 `/auth` 路径由 `HttpListener` 返回 404**，不会得到 `{"result":"deny"}`。
10. **`Base64Url.Decode` 忽略空白字符**（`Convert.FromBase64String` 的既有行为），43 字符长度检查不能保证字符集合法。
11. **内置角色 JSON 与代码兜底默认值漂移**：`src/builtin/roles/*.json` 使用 `FMO/SERVER_INFO/#`，`AclStore.LoadBuiltinDefaults()` 使用 `FMO/SERVER_INFO`。
12. **归档文件轮转不处理单条超限**：只有已写入过内容（`Bytes > 0`）才会因超限触发轮转。
13. **归档记录降级只执行一次**：摘要仍超限时不再截断。

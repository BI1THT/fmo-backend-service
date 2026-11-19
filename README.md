# FMO Server Authorizer Service

> [English](README_en.md)

**v1.1.1** | .NET 10.0 | Ed25519 | CBOR | Self-contained Single Binary

---

FMO（FM Over Internet）Server Authorizer Service 是一个独立的设备认证器，专为业余无线电 FMO 数字通联网络设计。

它通过 **根证书 → 中间证书 → 用户/设备证书** 三层证书链，实现完全离线、去中心化的设备身份验证。无需任何实时运营权威中心，每个爱好者都能安全地部署自己的服务器，在业余无线电世界里构建真正的零信任登录模式。

```
设备 ──MQTT CONNECT──▶ EMQX Broker ──POST /auth──▶ SAS
  (username+password)         HTTP 回调           证书链验证 + ACL 生成
```

---

## 为什么需要它？

传统数字通联网络（如 D-Star、YSF 等）通常依赖中心认证服务器来验证设备身份，这带来几个痛点：

| 痛点 | 说明 |
|------|------|
| **单点故障** | 中心服务宕机，所有用户无法登录 |
| **持续维护** | 需要专人 7×24 小时运维认证基础设施 |
| **外部依赖** | 个人或小团体难以快速搭建独立可信的网络 |

FMO Server Authorizer Service 把信任锚点从"网络上的中心服务器"下沉到"你手中的根证书"，让去中心化的安全认证成为现实。

## 核心思想：三重证书链认证

本服务采用经典的 PKI（公钥基础设施）信任模型：

```
根证书 (Root CA)
 └─ 中间证书 (Intermediate CA)
     └─ 用户/设备证书 (User/Device Certificate)
```

- **根证书** – 信任的最终锚点，由网络创建者离线安全保存，通常不直接签发用户证书。
- **中间证书** – 由根证书签发，用于日常的用户和设备管理，可定期轮换或为不同子网签发。
- **用户/设备证书** – 由中间证书签发，绑定到具体电台设备或操作员呼号，用于每次连接时的身份证明。

验证过程完全离线：认证器启动时只需加载根证书，即可通过校验证书链的签名、有效期及吊销状态，独立判断任何一台 FMO 设备的合法身份——无需查询任何在线数据库。

## "零信任"登录模式

这里"零信任"的含义是 **"从不信任，始终验证"**：

- 不信任网络位置（无论请求来自内网还是公网）
- 不信任会话状态（没有"一次认证，长期有效"的令牌）
- 每次连接请求都必须携带有效的设备证书，由本服务独立完成验证

只有持有合法证书的设备才能建立通联，即使网络环境不完全受控，安全性也能得到保障。

## 特性

- 完全离线验证 – 无需互联网连接，纯本地证书链校验
- 零信任架构 – 每次连接强制验证，杜绝未授权设备接入
- 轻量易部署 – 单一二进制文件，配置简单，适合嵌入式或轻量服务器
- 三层 PKI 证书链 – Root CA → Intermediate CA → User Cert
- Ed25519 高性能签名 – 现代椭圆曲线，安全且快速
- CBOR 紧凑编码 – 比 JSON 更紧凑，适合嵌入式场景
- CRL 吊销列表 – 支持证书吊销检查，定时刷新
- 登录审计归档 – 按呼号保存完整登录报文与证书链，日志带 Root SN 和请求 ID
- EMQX HTTP 认证集成 – 作为 EMQX Broker 认证回调即插即用
- 集群支持 – 多个 MQTT Broker 共享同一 SAS 实例进行认证
- OTA 自动更新 – 内置版本检查与自动升级
- 跨平台 – Windows / Linux / macOS (x64 & ARM64)
- Docker Compose 部署 – 一次编排 SAS 与 EMQX，并自动配置内部 HTTP 认证回调
- 持久化运行配置 – `sas-data` 与 `emqx-data` 卷保留配置、证书和 Broker 数据
- 镜像化更新 – 通过拉取最新 GHCR 镜像并由 Compose 按需重建服务，减少人工操作和业务恢复时间

## 典型部署场景

### 个人自建 FMO 网关

生成自己的根证书，为家中多台 FMO 设备签发证书。只有你自己的设备能接入。

### 俱乐部共享反射器

俱乐部管理员持有根证书，为会员签发中间证书和用户证书，会员凭证书接入俱乐部资源。

### 应急通信现场网

临时架设应急网络时，现场指挥快速生成证书体系，所有参勤电台凭预置证书安全组网，不依赖外部网络。

## 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | .NET 10.0 (self-contained, 无需安装) |
| 签名算法 | Ed25519 ([Chaos.NaCl](https://www.nuget.org/packages/Chaos.NaCl.Standard)) |
| 序列化 | CBOR ([System.Formats.Cbor](https://www.nuget.org/packages/System.Formats.Cbor)) |
| HTTP 服务器 | HttpListener (内置) |
| 发布方式 | 单文件自包含二进制 (PublishSingleFile) |

---

## 获取与安装

### 从设备后台获取（推荐）

在 FMO 设备管理后台可一键获取对应平台的安装脚本与预配置参数，开箱即用。

### 下载预编译二进制

从 Releases 下载对应平台：

| 平台 | 文件 | 说明 |
|------|------|------|
| Windows x64 | `sas-win-x64.zip` | 解压后双击 `Sas.exe` |
| Linux x64 | `sas-linux-x64.tar.gz` | `tar xzf` 后直接运行 `./Sas` |
| Linux ARM64 | `sas-linux-arm64.tar.gz` | 树莓派等，同上 |
| macOS Apple Silicon | `sas-osx-arm64.tar.gz` | M1/M2/M3/M4，终端运行 `./Sas` |
| macOS Intel | `sas-osx-x64.tar.gz` | Intel Mac，同上 |

下载后无需安装 .NET，解压即用。

### 自行编译

```bash
# 全平台打包（输出到 bin/ 目录）
./scripts/publish.ps1

# 单平台编译（自包含，无需安装 .NET 运行时）
dotnet publish src/Sas.csproj -c Release -r <RID> --self-contained -p:PublishSingleFile=true -o out
```

支持的 RID（Runtime Identifier）：

| RID | 平台 |
|-----|------|
| `win-x64` | Windows x64 |
| `linux-x64` | Linux x64 |
| `linux-arm64` | Linux ARM64 |
| `osx-arm64` | macOS Apple Silicon |
| `osx-x64` | macOS Intel |

---

## 快速开始

### Windows 桌面

```
双击 Sas.exe → 交互式配置 → 自动启动
```

再次双击直接启动，无需重新配置。

### Linux 命令行

```bash
# 首次运行（写入配置）
./Sas --server-uid 12345 --server-callsign BG5ESN \
      --mqtt-host your-mqtt-broker.com --cert-fingerprint gjJGc7...base64url...xY

# 之后（配置已持久化到 ~/.sas/config.json）
./Sas
```

### 验证服务是否正常

```bash
curl -X POST http://127.0.0.1:8080/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"BG6VMZ","password":"...base64url..."}'
# → {"result":"deny"} （无有效证书时拒绝，说明服务正常运行）
```

---

## Docker Compose 部署

仓库提供 `docker-compose.yml`，一次启动 SAS、EMQX 和 FMO Audit Service (FAS)。三个服务位于同一内部 Docker 网络；EMQX 的 HTTP 认证器已配置为调用 `http://sas:8080/auth`，无需在 Dashboard 中重复创建认证器。

```bash
# 创建实际部署配置并填写服务器 UID、呼号、证书指纹和 EMQX Dashboard 密码
cp .env.example .env

# 启动 SAS、EMQX 与 FAS
docker compose up -d

# 查看服务日志
docker compose logs -f sas emqx fas
```

Windows PowerShell 可用：

```powershell
Copy-Item .env.example .env
```

对外端口：

| 服务 | 地址 | 用途 |
|------|------|------|
| EMQX MQTT | `tcp://<server>:1883` | FMO 设备连接 |
| EMQX Dashboard | `http://<server>:18083` | 使用 `.env` 中的 Dashboard 账号登录 |
| FAS Web UI | `http://<server>:9527` | 初始化管理员并配置审计服务 |

SAS 的 HTTP 认证端口仅在 Compose 内部网络开放，不能从宿主机直接访问。`sas-data` 卷持久化 SAS 配置和根证书，`emqx-data` 卷持久化 EMQX 数据；不要删除这些卷，除非需要完全重新初始化。

### FAS 配置

[FMO Audit Service (FAS)](https://github.com/bi9bbl/fmo-audit-service) 已加入此 Compose 网络，但不会接收初始化参数。先在 `http://<server>:18083` 创建 API Key / Secret，再访问 FAS Web UI 完成管理员初始化和 EMQX 连接配置。

FAS 的 EMQX 目标 URL 必须填写：

```text
http://emqx:18083
```

`emqx` 是 Compose 服务名，Docker 内部 DNS 会将它解析到 EMQX 容器。不要填写 `http://localhost:18083`，它会指向 FAS 容器自身；也不需要填写宿主机 IP。

更新时先拉取最新镜像，再由 Compose 仅重建需要更新的服务：

```bash
docker compose pull
docker compose up -d
```

该流程将拉取与重建统一为两条命令，避免手动停止、删除和重新创建容器，可减少维护期间的操作次数和业务恢复时间；单实例服务在自身重建期间仍会有短暂连接中断。

---

## EMQX 配置

在 EMQX Dashboard 中配置 HTTP 密码认证：

```
认证类型: Password-Based
认证机制: HTTP
方法: POST
URL: http://<sas-host>:8080/auth
Headers: { "content-type": "application/json" }
Body: { "username": "${username}", "password": "${password}" }
```

---

## 配置参考

首次运行时 SAS 将配置写入 `~/.sas/config.json`（Windows 上为 `%USERPROFILE%\.sas\config.json`）。该文件是唯一真相源——后续启动无需任何参数。

### config.json 结构

```json
{
  "server": {
    "uid": 0,
    "callsign": "",
    "issuerSn": 0,
    "certFingerprint": "",
    "admins": [{ "uid": 0, "certFingerprint": "", "role": "admin" }]
  },
  "mqtt": {
    "host": "",
    "port": 1883,
    "clusters": [{"uid": 0, "callsign": "", "mqtt_host": "", "mqtt_port": 1883, "certFingerprint": ""}]
  },
  "trust": { "allowIssuerSn": [], "rootsDir": "~/.sas/roots" },
  "crl": { "refreshSec": 14400, "mode": "soft" },
  "http": {
    "addr": "0.0.0.0",
    "port": 8080,
    "ttlSec": 14400,
    "responseTemplate": "emqx",
    "maxBodyBytes": 65536,
    "maxPasswordBytes": 32768,
    "maxConcurrent": 128,
    "rateLimit": {
      "enabled": true,
      "globalPerMinute": 600,
      "breakerEnabled": true,
      "breakerFailures": 20,
      "breakerWindowSec": 300,
      "breakerBanSec": 600
    }
  },
  "update": { "enabled": true },
  "log": { "level": "Info" },
  "archive": {
    "enabled": true,
    "dir": "/data/sas/archive",
    "recordDenied": true,
    "recordDeniedPayload": false,
    "deniedPayloadSampleRate": 0.0,
    "retentionDays": 30,
    "maxFileBytes": 16777216,
    "maxRecordBytes": 16384
  }
}
```

### 必填项

| 字段 | 说明 | 从哪获取 |
|------|------|----------|
| `server.uid` | 服务器唯一 ID | FMO 管理后台 |
| `server.callsign` | 服务器呼号 | 同上，如 `BG5ESN` |
| `mqtt.host` | MQTT Broker 地址 | 你的 Broker IP 或域名 |
| `server.certFingerprint` | 服务器证书 SHA-256 指纹 (base64url) | FMO 后台「证书指纹」 |

### CLI 参数

| 参数 | 对应字段 | 默认值 |
|------|----------|:------:|
| `--server-uid` | `server.uid` | 必填 |
| `--server-callsign` | `server.callsign` | 必填 |
| `--mqtt-host` | `mqtt.host` | 必填 |
| `--cert-fingerprint` | `server.certFingerprint` | 必填 |
| `--mqtt-port` | `mqtt.port` | 1883 |
| `--http-port` | `http.port` | 8080 |
| `--http-addr` | `http.addr` | 0.0.0.0 |
| `--http-ttl` | `http.ttlSec` | 14400 |
| `--allow-issuer-sn` | `trust.allowIssuerSn` | 全部 |
| `--roots-dir` | `trust.rootsDir` | `~/.sas/roots` |
| `--issuer-sn` | `server.issuerSn` | 0 |
| `--crl-refresh` | `crl.refreshSec` | 14400 |
| `--crl-mode` | `crl.mode` | soft |
| `--log-level` | `log.level` | Info |
| `--archive-dir` | `archive.dir` | `~/.sas/archive` |
| `--archive-retention` | `archive.retentionDays` | 30 |

> **配置热更新**：当 `~/.sas/config.json` 已存在时，再次使用 CLI 参数启动会自动更新对应字段并保存，无需手动编辑配置文件。

### 登录审计与归档

每次 HTTP 认证都会生成一条结构化日志。成功登录会把完整的数字签名报文写入归档文件；失败登录默认只写摘要，避免高频失败撑大磁盘。

日志中可以看到用户证书链所属的 Root CA 和 Intermediate CA，以及用于关联归档记录的请求 ID：

```text
[INFO ] HTTP auth: allow callsign=BG6VMZ rootSn=1 rootFp=1a2b3c4d rootName=BG5ESN issuerSn=1001 issuerFp=7f8e9d0c issuerName=bd4wpw payloadLen=3120 payloadSha256=3f2a9c1d4b5e6f70 passwordLen=4160 req=a1b2c3d4e5f6
[WARN ] HTTP auth: deny callsign=BG6VMZ rootSn=1 rootFp=1a2b3c4d rootName=BG5ESN issuerSn=1001 issuerFp=7f8e9d0c issuerName=bd4wpw payloadLen=3120 payloadSha256=3f2a9c1d4b5e6f70 passwordLen=4160 req=0f9e8d7c6b5a reason="timestamp expired"
```

`rootFp` / `issuerFp` 是证书 fingerprint 的前 8 位，用于区分 Sn 相同的不同 CA。

认证入口的安全限制：

- `username` 最长 32 个 UTF-8 字节，只允许 `A-Z 0-9 / -`，非法请求直接拒绝且不归档；
- 默认全局限流 600 次/分钟；
- 同一呼号在证书链校验通过后，5 分钟内失败 20 次会临时封禁 10 分钟；无法证明持有该呼号证书的早期失败只受全局限流约束，避免伪造呼号误伤正常用户；
- `http.maxPasswordBytes` 限制 password 的 UTF-8 字节数，超长直接拒绝；
- 外部字段写入日志前统一转义，避免换行/控制字符注入。

归档按呼号和日期分组，每行是一个独立 JSON 对象：

```text
~/.sas/archive/
  BG6VMZ/
    2026-11-18.jsonl
  BD4WPW/
    2026-11-18.jsonl
```

目录名使用大写呼号，`/` 替换为 `_`（例如 `BG6VMZ/P` → `BG6VMZ_P`）。合法呼号字符集不含 `_`，因此不会产生目录冲突；记录中的 `callsign` 字段保留原始呼号。

```json
{
  "v": 1,
  "ts": "2026-11-18T20:34:56.789+08:00",
  "requestId": "a1b2c3d4e5f6",
  "callsign": "BG6VMZ",
  "result": "allow",
  "reason": null,
  "rootSn": 1,
  "rootFp": "1a2b3c4d5e6f7890a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e",
  "rootName": "BG5ESN",
  "issuerSn": 1001,
  "issuerFp": "7f8e9d0c1b2a34560f1e2d3c4b5a69788697a8b9c0d1e2f30415263748596071",
  "issuerName": "bd4wpw",
  "userUid": 50001,
  "role": "user",
  "claimedRole": "user",
  "targetCallsign": "BG5ESN",
  "targetUid": 5001,
  "targetUrl": "fmo.example.com",
  "targetPort": 1883,
  "timestamp": 1783291399,
  "passwordLength": 4160,
  "passwordSha256": "9c1d4b5e6f70a1b2",
  "payloadLength": 3120,
  "payloadSha256": "3f2a9c1d4b5e6f70",
  "password": "eyJjZXJ0UGFja2FnZSI6...",
  "payload": { "certPackage": { "...": "完整原始报文" } }
}
```

- 成功登录会保存完整的 `password` 和 `payload`，可直接用于复现验签或排查。
- 失败登录默认只保存摘要：`password` 和 `payload` 为 `null`，但保留长度、`passwordSha256`、`payloadSha256`、失败原因和证书链信息。需要完整失败报文时设置 `archive.recordDeniedPayload=true`，或用 `archive.deniedPayloadSampleRate` 按比例采样。
- 无法解析的畸形请求只写日志，不归档。
- SAS 不记录来源 IP。需要定位设备真实 IP 时，请在 EMQX 的客户端列表或连接日志中查询。
- 归档目录在 Linux 上创建为 `0700`，文件为 `0600`。报文不包含私钥，但包含完整证书链和签名，请勿公开分享。
- `archive.retentionDays` 为保留天数，`archive.maxFileBytes` 为单文件目标上限（超出后追加 `.1`、`.2` 后缀；单条记录不可拆分，因此文件可能超出上限最多一条记录的大小），`archive.maxRecordBytes` 为单条记录上限（超出时依次降级为摘要、裁剪摘要和核心字段记录，始终输出合法 JSON）。
- Docker 中归档位于 `sas-data` 卷内；如需按本地日期切分文件，请设置 `TZ`（Compose 默认 `Asia/Shanghai`）。

查看最近的登录记录：

```bash
tail -n 20 ~/.sas/archive/BG6VMZ/2026-11-18.jsonl | jq .
```

### 管理员管理

SAS 提供交互式管理员管理命令，用于配置额外的管理员权限：

```bash
# 添加管理员（交互式）
sas --add-admin [--config <path>]

# 删除管理员（交互式）
sas --remove-admin [--config <path>]

# 列出当前管理员
sas --list-admins [--config <path>]
```

- **super 角色**由服务器自身的 UID 与证书指纹共同决定（`user.uid == server.uid` 且证书指纹等于 `server.certFingerprint`），无需手动配置
- 管理员列表仅存储普通管理员（admin 角色），存储在 `config.json` 的 `Server.admins` 数组中；条目按 UID + 证书指纹匹配
- 可通过 `--config <path>` 指定非默认位置的配置文件

Docker Compose 部署使用运行中的 SAS 容器进行交互式管理：

```bash
docker exec -it fmo-sas dotnet sas.dll --add-admin
docker exec -it fmo-sas dotnet sas.dll --remove-admin
docker exec -it fmo-sas dotnet sas.dll --list-admins
```

### 集群管理

如果你有多个 MQTT Broker 共用同一个 SAS 实例，可以添加集群节点：

```bash
# 添加集群节点（交互式）
sas --add-cluster [--config <path>]

# 删除集群节点（交互式）
sas --remove-cluster [--config <path>]

# 列出当前集群节点
sas --list-clusters [--config <path>]
```

- 集群节点信息存储在 `config.json` 的 `Mqtt.clusters` 数组中
- 添加后，连接到这些 Broker 的设备也能通过本 SAS 完成认证
- 集群节点的 UID 与证书指纹同时匹配时，在该节点上获得 super 角色

使用 Docker Compose 部署时，可将其他独立 FMO 服务的公开 MQTT 地址登记到共享的 SAS 配置卷中：

```bash
# 按提示输入外部 FMO 服务的 UID、呼号、MQTT 主机、端口和证书指纹
docker exec -it fmo-sas dotnet sas.dll --add-cluster

# 查看或删除已登记的外部服务
docker exec -it fmo-sas dotnet sas.dll --list-clusters
docker exec -it fmo-sas dotnet sas.dll --remove-cluster

# 使常驻 SAS 进程重新加载修改后的配置
docker compose restart sas
```

外部服务的 MQTT Host 应填写可从设备访问的域名或 IP 地址，而不是本 Compose 网络中的服务名。

### 启动地址显示

当 `http.addr` 配置为 `0.0.0.0` 时，SAS 启动时会列出本机所有可用的 IPv4 地址及对应的认证端点 URL，方便确认访问地址。

---

## OTA 自动更新

SAS 内置版本检查与自动更新机制：

```bash
# 手动检查并更新到最新版本
sas --update
```

- **自动检查**：每次启动时自动检查新版本，发现更新会提示升级命令
- **关闭自动检查**：在 `config.json` 中设置 `"update": { "enabled": false }`
- **Docker 环境**：自动检测 Docker 运行环境，提示使用 `docker pull` 方式更新

---

## 测试

`test-case/` 目录包含集成测试工具和脚本：

| 工具/脚本 | 用途 |
|-----------|------|
| `FingerprintTool/` | 证书指纹计算工具 |
| `HttpChecker/` | HTTP 认证请求模拟器 |
| `run-test.ps1` | 正向测试（有效证书认证通过） |
| `run-test-negative.ps1` | 负向测试（无效/过期证书被拒绝） |
| `run-user-sim.ps1` | 用户模拟测试 |
| `send-auth.ps1` | 发送单次认证请求 |

运行测试：

```powershell
cd test-case
./run-test.ps1
./run-test-negative.ps1
```

---

## 目录结构

```
fmo-server-authorizer-service/
├── src/                            ← 源代码
│   ├── Sas.csproj                  ← 项目文件 (.NET 10.0)
│   ├── Program.cs                  ← 入口：CLI 解析 + 交互配置 + 启动
│   ├── Server/                     ← HTTP 监听器与限流
│   │   ├── HttpServer.cs           ← /auth 端点
│   │   └── AuthRateLimiter.cs      ← 全局限流 + 呼号熔断
│   ├── Messages/                   ← HTTP 认证载荷 DTO
│   ├── Trust/                      ← 证书验证 + CRL 管理
│   │   ├── RootCaStore.cs          ← Root CA 加载
│   │   ├── CertVerifier.cs         ← 证书链验证
│   │   └── CrlManager.cs           ← CRL 下载/缓存/吊销检查
│   ├── Auth/                       ← 认证处理 + ACL
│   │   ├── HttpAuthHandler.cs      ← 认证核心逻辑
│   │   ├── AuthRequestContext.cs   ← 请求上下文（request ID / 归档字段）
│   │   ├── CallsignValidator.cs    ← 呼号格式与长度校验
│   │   ├── HttpProofVerifier.cs    ← Ed25519 签名验证
│   │   ├── AclStore.cs             ← 角色权限 (super/admin/user)
│   │   └── EmqxResponseTemplate.cs ← EMQX 响应格式
│   ├── certs/                      ← 证书数据结构 + Ed25519 + Base64Url
│   ├── Logging/                    ← 日志与登录归档
│   │   ├── Logger.cs               ← 控制台日志
│   │   ├── LogSafe.cs              ← 日志字段转义
│   │   └── AuthArchive.cs          ← 按呼号归档登录报文
│   └── builtin/                    ← 内置数据
│       ├── roots/bg5esn.json       ← 内置 Root CA
│       └── roles/                  ← 角色权限定义 (super/admin/user)
├── scripts/
│   ├── publish.ps1                 ← 多平台编译打包
│   ├── install.sh                  ← Linux/macOS 安装脚本
│   └── install.ps1                 ← Windows 安装脚本
├── config/
│   └── config.example.json         ← 配置文件示例
├── test-case/                      ← 集成测试工具
├── docs/                           ← 详细文档
├── Sas.sln                         ← Visual Studio 解决方案
└── README.md
```

### 运行时目录

```
~/.sas/
├── config.json            ← 配置文件（唯一真相源）
├── roots/                 ← Root CA 证书
│   └── bg5esn.json
├── roles/                 ← 角色权限定义
│   ├── super.json
│   ├── admin.json
│   └── user.json
├── crl/                   ← CRL 缓存（按证书指纹，自动刷新）
│   ├── root-BG5ESN-1a2b3c4d5e6f7890/
│   │   ├── root.json
│   │   └── meta.json
│   └── intermediate-bd4wpw-7f8e9d0c1b2a3456/
│       ├── intermediate.json
│       └── meta.json
└── archive/               ← 登录报文归档（按呼号/日期）
    └── BG6VMZ/
        └── 2026-11-18.jsonl
```

`crl/` 下的缓存目录以证书指纹命名（`{type}-{safeName}-{fp16}`）。旧版本的 `crl/{sn}/` 缓存会被忽略并重新拉取。使用 `crl.mode=strict` 时，升级后首次启动到 CRL 拉取完成之间会拒绝认证；建议先观察日志中的 `Root CRL updated`，或临时切到 `soft` 预热后再切回 `strict`。

---

## 故障排查

| 症状 | 检查 |
|------|------|
| 启动后立即退出 | `sas --help` 确认参数；看是否缺必填项 |
| `Roots directory not found` | Root CA 未安装，确认内置证书存在 |
| `Root CA self-signature failed` | 证书文件损坏，重新获取 |
| `curl` 返回空或拒绝连接 | 检查端口 8080 是否被防火墙阻挡 |
| CRL 刷新 404 | `soft` 模式下正常，不影响服务运行；`strict` 模式下会拒绝认证，直到 CRL 发布并成功获取 |
| 认证始终 deny | 检查证书链是否完整、证书是否过期或被吊销；用日志中的 `req` 到归档里查完整报文 |
| 归档目录为空 | 检查 `archive.enabled`；只有能解析出 password JSON 的请求才会归档 |

---

## 注意事项

1. **无敏感数据**：`config.json` 中所有字段均为公开信息（呼号、证书指纹、网络地址等），不包含私钥或密码。安全性由设备端持有的私钥保证。
2. **内网部署**：HTTP 端点应监听 `127.0.0.1` 或内网地址，不直接暴露到公网。
3. **真相源**：首次初始化后，可通过编辑 `config.json` 修改配置（重启生效），也可通过 CLI 参数重新启动来自动更新配置。
4. **升级**：`sas --update` 自动下载最新版本并重启（或关闭自动检查：`update.enabled = false`）。
5. **设备侧**：FMO 设备固件需使用 SAS HTTP 认证器模式（MQTT CONNECT 时 username/password 携带证书信息）。
6. **登录归档**：成功登录保存完整报文，失败登录默认只保存摘要。归档文件包含完整证书链和 proof 签名（不含私钥），仅用于审计和故障排查。请限制归档目录访问权限，并按需调整 `archive.retentionDays`、`archive.maxFileBytes` 与 `archive.maxRecordBytes`。
7. **入口防护**：`username` 最长 32 个 UTF-8 字节且只允许呼号字符；全局限流默认 600 次/分钟。同一呼号只有在证书链校验通过后连续失败才会临时熔断，早期失败不会因伪造呼号误伤他人。阈值可在 `http.rateLimit` 中调整。

---

## 完整文档

- [SAS HTTP 认证协议](docs/V4.0%20SAS%20HTTP%20Authentication.md)
- [SAS 开发文档](docs/V4.0%20SAS.NET%20Development.md)
- [SAS OTA 更新机制](docs/V4.0%20SAS%20OTA%20Update.md)
- [V4 签名与证书协议](docs/V4.0%20Protocol%20-%20Signatures%20%26%20Certificates.md)
- [V4 Root CRL 格式](docs/V4.0%20Protocol%20Root%20CRL%20Formate.md)
- [V4 Intermediate CRL 格式](docs/V4.0%20Protocol%20Intermediate%20CRL%20Formate.md)

---

## License

本项目采用 [GPL-3.0](LICENSE) 许可证。

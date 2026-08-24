# WARP DDNS Deploy

基于 Python 编写的 Cloudflare WARP IP 优选与 DDNS 自动更新服务。该项目能定期扫描、筛选出 Cloudflare WARP 延迟最低的可用 IP 节点，并通过 Cloudflare API 将优选出来的 IP 自动绑定更新到指定的域名解析（DDNS）上。

## 核心特性

*   **纯 Python 实现 WireGuard 协议测速**: 不依赖系统的 WireGuard 内核模块及命令行工具 (`wg`)。通过 `cryptography` 密码学库，手动构建底层 WG 握手包 (Noise 协议)，通过 UDP 原生异步收发，实现极低开销和精准测速。
*   **高并发异步测速**: 基于 `asyncio` 并发控制，快速完成多 IP 初筛和深度复测，并根据成功率、延迟中位数、抖动严格选优。
*   **轻量级 Docker 部署**: 提供基于 `python:3.12-slim` 的轻量镜像方案，且利用预编译依赖（无需软路由本地编译 rust/gcc）。
*   **精准测速的网络优化**: 容器采用 `network_mode: "host"` 模式运行，避免 Docker Bridge 的 NAT 转换导致 UDP RTT 测速失真。

## 部署与使用

### 1. 环境变量配置 (`.env`)

在使用前，需要创建一个 `.env` 文件补充完整，填入 Cloudflare 相关的 API 信息：

```env
# Cloudflare API 配置
CF_TOKEN=你的_Cloudflare_API_Token
ZONE_ID=你的_Zone_ID
RECORD_ID=你的_DNS_Record_ID
RECORD_NAME=需要更新的域名 (如 warp.example.com)

# 测速与解析更新的间隔 (分钟)
INTERVAL_MINUTES=60
```

### 2. 使用 Docker Compose 运行

确保系统中已经安装好 Docker 和 Docker Compose，然后在项目根目录下运行：

```bash
docker-compose up -d --build
```

运行后，服务会以后台模式持续运行，并通过日志输出当前测速和优选结果：

```bash
docker-compose logs -f
```
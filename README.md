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

### 3. 使用 Docker Compose 运行

确保系统中已经安装好 Docker 和 Docker Compose，然后在项目根目录下运行：


### 2. 参数获取指南

#### CF_TOKEN (Cloudflare API Token)
1. 登录 [Cloudflare 控制台](https://dash.cloudflare.com/)。
2. 点击右上角的 "我的个人资料" -> 选择左侧边栏的 "API 令牌" (API Tokens)。
3. 点击 "创建令牌" (Create Token)。
4. 在最下方的 "自定义令牌" (Custom Token) 处点击 "开始使用"。
5. **权限设置** (Permissions)：
   * 选择 **Zone** -> **DNS** -> **编辑 (Edit)**。
6. **区域资源** (Zone Resources)：
   * 选择 **Include** -> **Specific Zone** -> 选择你的目标域名（例如 `example.com`）。
7. 点击 "继续以摘要" -> "创建令牌"。
8. 复制生成的 Token，这就是 `CF_TOKEN`，**注意该 Token 只会显示一次，请妥善保存**。

#### ZONE_ID (区域 ID)
1. 登录 Cloudflare 后，在主页点击你的主域名（例如 `example.com`）。
2. 在该域名的**概述 (Overview)** 页面。
3. 往右下方滑动页面，找到 **API** 区域。
4. 复制其中的 **区域 ID (Zone ID)**。

#### RECORD_NAME (解析域名)
你需要更新的具体子域名，例如 `warp.example.com`。

#### RECORD_ID (DNS 记录 ID)
1. 确保在 Cloudflare 的 "DNS -> 记录" 页面已经手动添加了该子域名的 A 记录（如 `warp`），IP 可以先随便填一个（如 `1.1.1.1`），**代理状态（Proxy status）必须设置为 "仅 DNS" (DNS only - 灰色云朵)**。
2. 可以在 Linux/macOS 终端运行以下 `curl` 命令来获取 `RECORD_ID`（将下面的替换为你获取到的信息）：
```bash
curl -X GET "https://api.cloudflare.com/client/v4/zones/<你的_ZONE_ID>/dns_records?name=<你的_RECORD_NAME>" \
     -H "Authorization: Bearer <你的_CF_TOKEN>" \
     -H "Content-Type: application/json"
```
在返回的 JSON 结果中，找到 `"id": "xxxxxxxxxxxxx"`，这串较长的字母数字组合即为 `RECORD_ID`。


```bash
docker-compose up -d --build
```

运行后，服务会以后台模式持续运行，并通过日志输出当前测速和优选结果：

```bash
docker-compose logs -f
```
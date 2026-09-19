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

## 更新日志

### v1.1.0 (2025-09-19) — 修复误判"IP 被封"导致频繁重新优选

本次更新修复了三个相互叠加的 bug，它们共同导致健康检查频繁将正常可用的 IP 误判为不可达，触发不必要的重新优选。

#### 🐛 Bug 1：`async_wireguard_ping` 异常死循环（最致命）

**问题**：`while True` 接收循环中 `except Exception: pass` 会静默吞掉 `ConnectionRefusedError` 等 socket 异常，由于没有任何 `await` 或 `break`，形成同步死循环，CPU 100% 占用，阻塞整个 asyncio 事件循环 → 所有并发探测全部超时失败。

**修复**：
- 增加 `recv_errors` 计数器，累计 5 次非超时异常后直接返回失败
- 每次异常后 `await asyncio.sleep(0.05)` 让出事件循环，防止 CPU 空转

#### 🐛 Bug 2：复测阶段并发风暴

**问题**：`scan_warp_ips` 复测阶段对同一 IP 的所有重复探测通过 `asyncio.gather` 同时并发发出（例如同一 IP 在几毫秒内发送 3 个 WireGuard 握手包）。由于脚本与 OpenClash 共用同一 WireGuard 密钥对，高频握手触发 Cloudflare 服务端速率限制，导致正常 IP 的探测被丢弃。

**修复**：
- 复测改为分轮进行：每轮对所有候选 IP 并发探测（不同 IP 之间并发安全），轮次之间间隔 1.5s
- 复测次数从 3 次提升到 5 次，采样更充分，排名更可靠

#### 🐛 Bug 3：健康检查误判逻辑

**问题**：健康检查发送 3 次探测（无间隔），要求至少 1 次成功，否则立即触发重新优选。由于 Bug 1 和 Bug 2 的存在，加上零间隔高频握手本身容易被 CF 限速，导致正常节点被频繁误判。

**修复**：
- **第一轮**：5 次探测，每次间隔 1.5s，要求至少 3/5 成功
- **确认轮**：首轮不达标时，等待 10s 后再做 3 次探测，要求至少 2/3 成功
- 只有两轮都不达标才触发重新优选，有效排除短暂网络抖动造成的误判
#!/usr/bin/env python3
import asyncio
import base64
import hashlib
import hmac
import ipaddress
import random
import secrets
import statistics
import struct
import time
import socket
import json
import urllib.request
import os
import signal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ================= 配置区 =================

# ---------- Cloudflare API 配置 (通过 .env 环境变量注入) ----------
# CF_TOKEN: Cloudflare API 令牌，用于调用 DDNS 更新接口
#   获取方式: Cloudflare 控制台 → 我的个人资料 → API 令牌 → 创建令牌
#            → 自定义令牌 → 权限选 Zone / DNS / Edit → 选择目标域名
CF_TOKEN = os.getenv("CF_TOKEN")

# ZONE_ID: Cloudflare 区域 ID，标识你的主域名所在的 DNS 区域
#   获取方式: Cloudflare 控制台 → 点击主域名 → 概述(Overview) 页面右下方 API 区域
ZONE_ID = os.getenv("ZONE_ID")

# RECORD_ID: 要更新的那条 DNS A 记录的唯一 ID
#   获取方式: 先在 Cloudflare DNS 页面手动创建一条 A 记录 (代理状态设为 "仅 DNS")
#            然后通过 API 查询:
#            curl -X GET "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/dns_records?name=<RECORD_NAME>" \
#                 -H "Authorization: Bearer <CF_TOKEN>" -H "Content-Type: application/json"
#            返回 JSON 中的 "id" 字段即为 RECORD_ID
RECORD_ID = os.getenv("RECORD_ID")

# RECORD_NAME: 需要自动更新 IP 的子域名，例如 "warp.example.com"
#   用途: 脚本优选出最佳 WARP IP 后，会将该域名的 A 记录更新为该 IP
RECORD_NAME = os.getenv("RECORD_NAME")

# INTERVAL_MINUTES: 自动测速 + DDNS 更新的循环间隔 (分钟)，默认 60 分钟
INTERVAL_MINUTES = int(os.getenv("INTERVAL_MINUTES", "60"))

# ---------- Telegram 机器人配置 (可选，不配置则仅自动运行) ----------
# TG_BOT_TOKEN: Telegram Bot 的 API Token
#   获取方式: 在 Telegram 中搜索 @BotFather → /newbot → 按提示创建 → 获得 Token
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip()

# TG_CHAT_ID: 接收通知消息的 Telegram 用户或群组的 Chat ID
#   获取方式: 向 @userinfobot 或 @RawDataBot 发送消息即可获得自己的 Chat ID
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "").strip()

# ---------- WireGuard / WARP 测速参数 (硬编码，与 OpenClash 节点配置一致) ----------
# PREFERRED_IP_PRIVATE_KEY: WireGuard 客户端私钥 (Base64)
#   用途: 构建 WG Handshake Initiation 包时用于密钥交换 (Noise_IK 协议)
#   来源: 从 Cloudflare WARP 客户端注册信息中提取，需与 OpenClash 中配置的 private-key 保持一致
#   注意: 此密钥同时被 OpenClash 的 WARP 节点使用，高频握手可能触发 CF 速率限制
PREFERRED_IP_PRIVATE_KEY = "8I2+WOh1grMu8HaW6JTwg+B3Oh7fOPnqj4xpMWn3FU0="

# PREFERRED_IP_PEER_PUBLIC_KEY: Cloudflare WARP 服务端公钥 (Base64)
#   用途: WG 握手时用于加密和验证服务端身份
#   来源: Cloudflare WARP 固定的服务端公钥，所有 WARP 用户共用，不会变化
#         可从 WARP 客户端配置或 wgcf 生成的配置文件中获取
PREFERRED_IP_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

# CF_WARP_IPV4_CIDRS: Cloudflare WARP 的 IPv4 Anycast 地址段列表
#   用途: 脚本从这些网段中随机抽取 IP 进行测速优选
#   来源: Cloudflare 官方公布的 WARP 服务 IP 段
#         参考 https://www.cloudflare.com/ips/ 以及社区整理的 WARP 专用段
CF_WARP_IPV4_CIDRS = ["162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24"]

# WARP_PORT: WARP WireGuard 服务的 UDP 端口号
#   Cloudflare WARP 支持多个端口: 500, 854, 859, 864, 878, 880, 890, 891, 894, 903,
#   908, 928, 934, 939, 942, 943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014,
#   1018, 1070, 1074, 1180, 1387, 1701, 1843, 2371, 2408, 2506, 3138, 3476, 3581,
#   3854, 4177, 4198, 4233, 4500, 5279, 5956, 7103, 7152, 7156, 7281, 7559, 8319, 8742, 8854, 8886
#   这里默认使用 2408，与 OpenClash 节点配置中的 port 一致
WARP_PORT = 2408

# ---------- WireGuard Noise 协议常量 (协议规范固定值，勿修改) ----------
# WG_CONSTRUCTION: Noise 协议框架标识符，指定使用的密码套件组合
#   含义: Noise_IK 握手模式 + psk2 预共享密钥混合 + X25519 密钥交换 + ChaChaPoly 加密 + BLAKE2s 哈希
#   参考: https://www.wireguard.com/protocol/ 及 Noise Protocol Framework 规范
WG_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"

# WG_IDENTIFIER: WireGuard 协议的全局标识字符串，用于初始化握手哈希链
#   作用: 作为 BLAKE2s 哈希的初始输入，确保 WG 握手与其他 Noise 协议实现隔离
WG_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"

# WG_LABEL_MAC1: MAC1 标签前缀，用于计算握手包的 mac1 字段
#   作用: mac1 = BLAKE2s-128(HASH("mac1----" || responder_public_key), message)
#         防止未授权的握手包消耗服务端资源 (DoS 防护的第一层)
WG_LABEL_MAC1 = b"mac1----"

def send_tg_msg(text):
    if not TG_BOT_TOKEN or not TG_CHAT_ID: return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    req = urllib.request.Request(url, data=json.dumps({"chat_id": TG_CHAT_ID, "text": text}).encode('utf-8'), headers={"Content-Type": "application/json"})
    try: urllib.request.urlopen(req, timeout=10)
    except Exception as e: print(f"⚠️ Telegram 消息发送失败: {e}")

async def poll_telegram(trigger_event):
    if not TG_BOT_TOKEN or not TG_CHAT_ID: return
    offset = 0
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/getUpdates"
    def fetch_updates():
        try:
            with urllib.request.urlopen(f"{url}?offset={offset}&timeout=30", timeout=35) as r: return json.loads(r.read().decode('utf-8'))
        except Exception: return None
    while True:
        try:
            data = await asyncio.to_thread(fetch_updates)
            if data and data.get("ok"):
                for update in data.get("result", []):
                    offset = update["update_id"] + 1
                    msg = update.get("message", {})
                    if str(msg.get("chat", {}).get("id", "")) == TG_CHAT_ID and msg.get("text", "").strip().lower() == "/warp":
                        send_tg_msg("⚡ 收到指令：立即中断休眠，强制重新优选 WARP 节点！")
                        trigger_event.set()
        except Exception: pass
        await asyncio.sleep(1)

def get_random_ips(count=100):
    networks = [list(ipaddress.ip_network(c).hosts()) for c in CF_WARP_IPV4_CIDRS]
    selected = []
    quotient, remainder = divmod(count, len(networks))
    for index, hosts in enumerate(networks):
        size = min(len(hosts), quotient + (1 if index < remainder else 0))
        selected.extend(str(ip) for ip in random.sample(hosts, size))
    random.shuffle(selected)
    return selected

def _blake2s(data, *, key=b"", digest_size=32): return hashlib.blake2s(data, key=key, digest_size=digest_size).digest()
def _hmac_blake2s(key, data): return hmac.new(key, data, hashlib.blake2s).digest()
def _kdf(chaining_key, input_material, outputs):
    temp_key = _hmac_blake2s(chaining_key, input_material)
    values = []; output_block = b""
    for i in range(1, outputs + 1):
        output_block = _hmac_blake2s(temp_key, output_block + bytes([i]))
        values.append(output_block)
    return tuple(values)
def _tai64n_now():
    s, n = divmod(time.time_ns(), 1_000_000_000)
    return struct.pack(">QI", s + 0x400000000000000A, n)

def build_wireguard_initiation(private_key_b64, peer_public_key_b64):
    static_private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64, validate=True))
    static_public = static_private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    responder_public_bytes = base64.b64decode(peer_public_key_b64, validate=True)
    responder_public = X25519PublicKey.from_public_bytes(responder_public_bytes)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    chaining_key = _blake2s(WG_CONSTRUCTION)
    handshake_hash = _blake2s(_blake2s(chaining_key + WG_IDENTIFIER) + responder_public_bytes)
    chaining_key = _kdf(chaining_key, ephemeral_public, 1)[0]
    handshake_hash = _blake2s(handshake_hash + ephemeral_public)
    chaining_key, key = _kdf(chaining_key, ephemeral_private.exchange(responder_public), 2)
    encrypted_static = ChaCha20Poly1305(key).encrypt(b"\0" * 12, static_public, handshake_hash)
    handshake_hash = _blake2s(handshake_hash + encrypted_static)
    chaining_key, key = _kdf(chaining_key, static_private.exchange(responder_public), 2)
    encrypted_timestamp = ChaCha20Poly1305(key).encrypt(b"\0" * 12, _tai64n_now(), handshake_hash)
    handshake_hash = _blake2s(handshake_hash + encrypted_timestamp)
    sender_index = secrets.token_bytes(4)
    message = struct.pack("<I", 1) + sender_index + ephemeral_public + encrypted_static + encrypted_timestamp
    mac1_key = _blake2s(WG_LABEL_MAC1 + responder_public_bytes)
    return message + _blake2s(message, key=mac1_key, digest_size=16) + (b"\0" * 16), (sender_index, ephemeral_private, static_private, chaining_key, handshake_hash)

def validate_wireguard_response(response, state):
    if len(response) != 92 or struct.unpack_from("<I", response)[0] != 2: return False
    sender_index, ephemeral_private, static_private, chaining_key, handshake_hash = state
    if response[8:12] != sender_index: return False
    responder_ephemeral_bytes = response[12:44]
    responder_ephemeral = X25519PublicKey.from_public_bytes(responder_ephemeral_bytes)
    handshake_hash = _blake2s(handshake_hash + responder_ephemeral_bytes)
    chaining_key = _kdf(chaining_key, responder_ephemeral_bytes, 1)[0]
    chaining_key = _kdf(chaining_key, ephemeral_private.exchange(responder_ephemeral), 1)[0]
    _kdf(chaining_key, static_private.exchange(responder_ephemeral), 1)[0]
    return True

async def async_wireguard_ping(ip, private_key_b64, peer_public_key_b64, timeout=1.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    max_recv_errors = 5  # 防止 ConnectionRefusedError 等异常导致死循环
    recv_errors = 0
    try:
        msg, state = build_wireguard_initiation(private_key_b64, peer_public_key_b64)
        start_time = time.perf_counter()
        await loop.sock_sendto(sock, msg, (ip, WARP_PORT))
        while True:
            elapsed = time.perf_counter() - start_time
            if elapsed >= timeout: return ip, -1
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout - elapsed)
                if validate_wireguard_response(data, state): return ip, round((time.perf_counter() - start_time) * 1000, 2)
            except asyncio.TimeoutError: return ip, -1
            except Exception:
                recv_errors += 1
                if recv_errors >= max_recv_errors: return ip, -1
                await asyncio.sleep(0.05)  # 让出事件循环，避免 CPU 空转死循环
    except Exception: return ip, -1
    finally: sock.close()

async def scan_warp_ips():
    sample_size = 100; concurrency = 25; finalists = 10; repeat_count = 5
    probe_interval = 1.5  # 每次复测探测之间的间隔（秒），避免触发 CF 速率限制
    print(f"[{time.strftime('%H:%M:%S')}] 📦 正在抽取 {sample_size} 个 IP 进行初筛...")
    ips = get_random_ips(sample_size)
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(ip):
        async with semaphore: return await async_wireguard_ping(ip, PREFERRED_IP_PRIVATE_KEY, PREFERRED_IP_PEER_PUBLIC_KEY)

    valid_results = sorted([(ip, lat) for ip, lat in await asyncio.gather(*(probe(ip) for ip in ips)) if lat >= 0], key=lambda x: x[1])
    if not valid_results:
        print("❌ 没有 IP 返回响应。"); return None, "❌ 没有 IP 返回响应。"
    
    finalist_ips = [ip for ip, _ in valid_results[:finalists]]
    print(f"[{time.strftime('%H:%M:%S')}] ✅ 初筛发现 {len(valid_results)} 个，复测前 {len(finalist_ips)} 名...")
    
    # ---- 复测：分轮串行探测，轮次间加间隔，避免并发风暴和 CF 速率限制 ----
    samples = {ip: [] for ip in finalist_ips}
    for round_idx in range(repeat_count):
        if round_idx > 0:
            await asyncio.sleep(probe_interval)  # 轮次间休息，避免同 key 高频握手
        # 每轮对所有 finalist 并发探测（不同 IP 之间并发是安全的）
        round_results = await asyncio.gather(*(probe(ip) for ip in finalist_ips))
        for ip, lat in round_results:
            if lat >= 0: samples[ip].append(lat)

    ranked = []
    for ip in finalist_ips:
        lats = samples[ip]
        ranked.append({
            "ip": ip, "successes": len(lats),
            "median_ms": round(statistics.median(lats), 2) if lats else None,
            "jitter_ms": round(statistics.pstdev(lats), 2) if len(lats) > 1 else 0.0,
        })
    ranked.sort(key=lambda item: (-item["successes"], item["median_ms"] if item["median_ms"] is not None else float("inf"), item["jitter_ms"]))
    
    best = ranked[0]
    res_msg = f"🎯 优选结果: {best['ip']}\n⏱ 成功率: {best['successes']}/{repeat_count} | 延迟: {best['median_ms']}ms | 抖动: {best['jitter_ms']}ms"
    print(res_msg)
    return best["ip"], res_msg

def update_local_proxy_file(ip):
    yaml_content = f"""proxies:
  - name: ☁️ WARP节点
    type: wireguard
    server: {ip}
    port: 2408
    ip: 172.16.0.2
    public-key: bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
    private-key: 8I2+WOh1grMu8HaW6JTwg+B3Oh7fOPnqj4xpMWn3FU0=
    udp: true
    mtu: 1280
    reserved: [79, 144, 83]
"""
    try:
        os.makedirs("/app/output", exist_ok=True)
        with open("/app/output/warp-node.yaml", "w", encoding="utf-8") as f:
            f.write(yaml_content)
        print("📁 OpenClash 本地代理配置 (warp-node.yaml) 更新成功！")
    except Exception as e:
        print(f"⚠️ 写入本地代理配置失败: {e}")

def update_cloudflare_ddns(ip):
    print(f"🌐 正在将优选 IP ({ip}) 更新到 Cloudflare DDNS...")
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records/{RECORD_ID}"
    req = urllib.request.Request(url, data=json.dumps({"type": "A", "name": RECORD_NAME, "content": ip, "ttl": 1, "proxied": False}).encode("utf-8"), headers={"Authorization": f"Bearer {CF_TOKEN}", "Content-Type": "application/json"}, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            if json.loads(r.read().decode("utf-8")).get("success"):
                print("🎉 DDNS 更新成功！\n"); return True, "🎉 DDNS 更新成功！"
            else:
                print("❌ DDNS 更新失败\n"); return False, "❌ DDNS 更新失败"
    except Exception as e: print(f"❌ 请求 Cloudflare API 异常: {e}\n"); return False, f"❌ 请求 Cloudflare API 异常: {e}"

async def main_loop():
    trigger_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGUSR1, lambda: trigger_event.set())
    if TG_BOT_TOKEN and TG_CHAT_ID: asyncio.create_task(poll_telegram(trigger_event))
    
    current_active_ip = None; force_rescan = True 
    
    # ---- 健康检查参数 ----
    HEALTH_PROBE_COUNT = 5        # 每轮探测次数
    HEALTH_PROBE_INTERVAL = 1.5   # 探测间隔（秒），避免 CF 速率限制
    HEALTH_MIN_SUCCESS = 3        # 至少需要成功的次数 (3/5)
    CONFIRM_WAIT = 10             # 首轮失败后等待多久再确认（秒）
    CONFIRM_PROBE_COUNT = 3       # 确认轮探测次数
    CONFIRM_MIN_SUCCESS = 2       # 确认轮至少成功次数 (2/3)
    
    async def health_check(ip, count):
        """对指定 IP 进行带间隔的多次探测，返回 (成功次数, 延迟列表)"""
        lats = []
        for i in range(count):
            if i > 0:
                await asyncio.sleep(HEALTH_PROBE_INTERVAL)
            _, lat = await async_wireguard_ping(ip, PREFERRED_IP_PRIVATE_KEY, PREFERRED_IP_PEER_PUBLIC_KEY, timeout=2.5)
            if lat >= 0:
                lats.append(lat)
        return len(lats), lats
    
    while True:
        try:
            need_rescan = force_rescan or (current_active_ip is None)
            if current_active_ip and not force_rescan:
                print(f"[{time.strftime('%H:%M:%S')}] 🔍 检测当前节点 ({current_active_ip}) ...")
                
                # ---- 第一轮：5次探测，间隔1.5s，至少3次成功 ----
                successes, lats = await health_check(current_active_ip, HEALTH_PROBE_COUNT)
                
                if successes >= HEALTH_MIN_SUCCESS:
                    med = round(statistics.median(lats), 2)
                    jit = round(statistics.pstdev(lats), 2) if len(lats) > 1 else 0.0
                    print(f"✅ 节点 {current_active_ip} 健康 ({successes}/{HEALTH_PROBE_COUNT}) | 延迟: {med}ms | 抖动: {jit}ms，继续休眠。\n")
                    need_rescan = False
                else:
                    print(f"⚠️ 首轮探测不佳 ({successes}/{HEALTH_PROBE_COUNT})，等待 {CONFIRM_WAIT}s 后确认...")
                    
                    # ---- 第二轮确认：等待后再测，排除短暂网络抖动 ----
                    await asyncio.sleep(CONFIRM_WAIT)
                    confirm_successes, confirm_lats = await health_check(current_active_ip, CONFIRM_PROBE_COUNT)
                    
                    if confirm_successes >= CONFIRM_MIN_SUCCESS:
                        all_lats = lats + confirm_lats
                        med = round(statistics.median(all_lats), 2)
                        jit = round(statistics.pstdev(all_lats), 2) if len(all_lats) > 1 else 0.0
                        print(f"✅ 确认轮通过 ({confirm_successes}/{CONFIRM_PROBE_COUNT})，节点仍可用 | 延迟: {med}ms | 抖动: {jit}ms\n")
                        need_rescan = False
                    else:
                        total_fail = f"{successes}/{HEALTH_PROBE_COUNT} + 确认 {confirm_successes}/{CONFIRM_PROBE_COUNT}"
                        msg = f"❌ 当前节点 {current_active_ip} 两轮探测均不达标 ({total_fail})，准备重新优选..."
                        print(msg); send_tg_msg(msg); need_rescan = True
                    
            if need_rescan:
                best_ip, stats_msg = await scan_warp_ips()
                if best_ip:
                    update_local_proxy_file(best_ip)
                    success_ddns, ddns_msg = update_cloudflare_ddns(best_ip)
                    
                    if success_ddns: 
                        current_active_ip = best_ip; force_rescan = False
                    send_tg_msg(f"{stats_msg}\n{ddns_msg}")
                else:
                    print("未找到有效节点。\n"); send_tg_msg(stats_msg)
        except Exception as e: print(f"异常: {e}\n"); send_tg_msg(f"❌ 异常: {e}")
            
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 进入休眠，等待 {INTERVAL_MINUTES} 分钟自动执行，或等待 Telegram 手动信号...\n")
        try:
            await asyncio.wait_for(trigger_event.wait(), timeout=INTERVAL_MINUTES * 60)
            print(f"\n[{time.strftime('%H:%M:%S')}] ⚡ 接收到手动触发信号，立即测速！")
            trigger_event.clear(); force_rescan = True
        except asyncio.TimeoutError: force_rescan = False 

if __name__ == "__main__": asyncio.run(main_loop())

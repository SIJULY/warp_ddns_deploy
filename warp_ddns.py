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

# ================= 配置区 (通过环境变量读取) =================
CF_TOKEN = os.getenv("CF_TOKEN")
ZONE_ID = os.getenv("ZONE_ID")
RECORD_ID = os.getenv("RECORD_ID")
RECORD_NAME = os.getenv("RECORD_NAME")
INTERVAL_MINUTES = int(os.getenv("INTERVAL_MINUTES", "60"))

TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "").strip()
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "").strip()

PREFERRED_IP_PRIVATE_KEY = "8I2+WOh1grMu8HaW6JTwg+B3Oh7fOPnqj4xpMWn3FU0="
PREFERRED_IP_PEER_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="

CF_WARP_IPV4_CIDRS = ["162.159.192.0/24", "162.159.193.0/24", "162.159.195.0/24", "188.114.96.0/24", "188.114.97.0/24"]
WARP_PORT = 2408

WG_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
WG_IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
WG_LABEL_MAC1 = b"mac1----"
# =============================================================

def send_tg_msg(text):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    data = json.dumps({"chat_id": TG_CHAT_ID, "text": text}).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"⚠️ Telegram 消息发送失败: {e}")

async def poll_telegram(trigger_event):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        return
    offset = 0
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/getUpdates"
    
    def fetch_updates():
        req_url = f"{url}?offset={offset}&timeout=30"
        try:
            with urllib.request.urlopen(req_url, timeout=35) as response:
                return json.loads(response.read().decode('utf-8'))
        except Exception:
            return None

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
        except Exception:
            pass
        await asyncio.sleep(1)

def get_random_ips(count=100):
    networks = [list(ipaddress.ip_network(cidr).hosts()) for cidr in CF_WARP_IPV4_CIDRS]
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
    now_ns = time.time_ns()
    seconds, nanoseconds = divmod(now_ns, 1_000_000_000)
    return struct.pack(">QI", seconds + 0x400000000000000A, nanoseconds)

def build_wireguard_initiation(private_key_b64, peer_public_key_b64):
    static_private = X25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64, validate=True))
    static_public = static_private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    responder_public_bytes = base64.b64decode(peer_public_key_b64, validate=True)
    responder_public = X25519PublicKey.from_public_bytes(responder_public_bytes)
    ephemeral_private = X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    chaining_key = _blake2s(WG_CONSTRUCTION)
    handshake_hash = _blake2s(chaining_key + WG_IDENTIFIER)
    handshake_hash = _blake2s(handshake_hash + responder_public_bytes)
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
    message += _blake2s(message, key=mac1_key, digest_size=16) + (b"\0" * 16)
    return message, (sender_index, ephemeral_private, static_private, chaining_key, handshake_hash)

def validate_wireguard_response(response, state):
    if len(response) != 92 or struct.unpack_from("<I", response)[0] != 2: return False
    sender_index, ephemeral_private, static_private, chaining_key, handshake_hash = state
    if response[8:12] != sender_index: return False
    responder_ephemeral_bytes = response[12:44]
    responder_ephemeral = X25519PublicKey.from_public_bytes(responder_ephemeral_bytes)
    handshake_hash = _blake2s(handshake_hash + responder_ephemeral_bytes)
    chaining_key = _kdf(chaining_key, responder_ephemeral_bytes, 1)[0]
    chaining_key = _kdf(chaining_key, ephemeral_private.exchange(responder_ephemeral), 1)[0]
    chaining_key = _kdf(chaining_key, static_private.exchange(responder_ephemeral), 1)[0]
    return True

async def async_wireguard_ping(ip, private_key_b64, peer_public_key_b64, timeout=1.5):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        msg, state = build_wireguard_initiation(private_key_b64, peer_public_key_b64)
        start_time = time.perf_counter()
        await loop.sock_sendto(sock, msg, (ip, WARP_PORT))
        while True:
            elapsed = time.perf_counter() - start_time
            if elapsed >= timeout: return ip, -1
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 1024), timeout - elapsed)
                if validate_wireguard_response(data, state):
                    return ip, round((time.perf_counter() - start_time) * 1000, 2)
            except asyncio.TimeoutError:
                return ip, -1
            except Exception: pass
    except Exception: return ip, -1
    finally: sock.close()

async def scan_warp_ips():
    sample_size = 100
    concurrency = 25
    finalists = 10
    repeat_count = 3

    print(f"[{time.strftime('%H:%M:%S')}] 📦 正在抽取 {sample_size} 个 IP 进行 UDP 握手初筛...")
    build_wireguard_initiation(PREFERRED_IP_PRIVATE_KEY, PREFERRED_IP_PEER_PUBLIC_KEY)
    ips = get_random_ips(sample_size)
    semaphore = asyncio.Semaphore(concurrency)

    async def probe(ip):
        async with semaphore:
            return await async_wireguard_ping(ip, PREFERRED_IP_PRIVATE_KEY, PREFERRED_IP_PEER_PUBLIC_KEY)

    results = await asyncio.gather(*(probe(ip) for ip in ips))
    valid_results = sorted([(ip, lat) for ip, lat in results if lat >= 0], key=lambda x: x[1])

    if not valid_results:
        msg = "❌ 没有 IP 返回可验证的 WireGuard 握手响应。"
        print(msg)
        return None, msg

    finalist_ips = [ip for ip, _ in valid_results[:finalists]]
    print(f"[{time.strftime('%H:%M:%S')}] ✅ 初筛发现 {len(valid_results)} 个 IP，正对前 {len(finalist_ips)} 名复测 {repeat_count} 次...")
    
    repeated = await asyncio.gather(*(probe(ip) for ip in finalist_ips for _ in range(repeat_count)))
    samples = {ip: [] for ip in finalist_ips}
    for ip, latency in repeated:
        if latency >= 0: samples[ip].append(latency)

    ranked = []
    for ip in finalist_ips:
        latencies = samples[ip]
        ranked.append({
            "ip": ip,
            "successes": len(latencies),
            "median_ms": round(statistics.median(latencies), 2) if latencies else None,
            "jitter_ms": round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0,
        })
    ranked.sort(key=lambda item: (-item["successes"], item["median_ms"] if item["median_ms"] is not None else float("inf"), item["jitter_ms"]))
    
    best = ranked[0]
    res_msg = f"🎯 优选结果: {best['ip']}\n⏱ 成功率: {best['successes']}/{repeat_count} | 延迟: {best['median_ms']}ms | 抖动: {best['jitter_ms']}ms"
    print(res_msg)
    return best["ip"], res_msg

def update_cloudflare_ddns(ip):
    print(f"🌐 正在将优选 IP ({ip}) 更新到 Cloudflare DDNS ({RECORD_NAME})...")
    url = f"https://api.cloudflare.com/client/v4/zones/{ZONE_ID}/dns_records/{RECORD_ID}"
    headers = {"Authorization": f"Bearer {CF_TOKEN}", "Content-Type": "application/json"}
    data = json.dumps({"type": "A", "name": RECORD_NAME, "content": ip, "ttl": 1, "proxied": False}).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="PUT")
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            resp_data = json.loads(response.read().decode("utf-8"))
            if resp_data.get("success"):
                msg = f"🎉 DDNS 更新成功！"
                print(msg + "\n")
                return True, msg
            else:
                msg = f"❌ DDNS 更新失败: {resp_data.get('errors')}"
                print(msg + "\n")
                return False, msg
    except Exception as e:
        msg = f"❌ 请求 Cloudflare API 发生异常: {e}"
        print(msg + "\n")
        return False, msg

async def main_loop():
    if not all([CF_TOKEN, ZONE_ID, RECORD_ID, RECORD_NAME]):
        print("❌ 环境变量未完全配置，请检查 .env 文件。")
        return
        
    print("==========================================")
    print("🐉 小龙女她爸 - WARP DDNS 自动化任务已启动")
    print(f"📌 目标域名: {RECORD_NAME}")
    print(f"⏱️  执行间隔: {INTERVAL_MINUTES} 分钟")
    
    trigger_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGUSR1, lambda: trigger_event.set())
    
    if TG_BOT_TOKEN and TG_CHAT_ID:
        asyncio.create_task(poll_telegram(trigger_event))
        print("🤖 Telegram 机器人监听已启动，随时发送 /warp 手动触发")
    print("==========================================\n")
    
    current_active_ip = None
    force_rescan = True 
    
    while True:
        try:
            # 核心修复点：如果没有可用 IP 兜底，强制进入扫描状态
            need_rescan = force_rescan or (current_active_ip is None)
            
            if current_active_ip and not force_rescan:
                print(f"[{time.strftime('%H:%M:%S')}] 🔍 正在检测当前在用节点 ({current_active_ip}) 的连通性...")
                
                # 为了计算抖动和准确延迟，改成连测3次
                latencies = []
                for _ in range(3):
                    _, lat = await async_wireguard_ping(current_active_ip, PREFERRED_IP_PRIVATE_KEY, PREFERRED_IP_PEER_PUBLIC_KEY, timeout=2.5)
                    if lat >= 0:
                        latencies.append(lat)
                
                if latencies:
                    median_ms = round(statistics.median(latencies), 2)
                    jitter_ms = round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0
                    
                    print(f"✅ 检查到上次推送的IP {current_active_ip} 状态良好 | 延迟: {median_ms}ms | 抖动: {jitter_ms}ms，无需更换，所以继续进入休眠。\n")
                    need_rescan = False
                else:
                    msg = f"❌ 当前节点 {current_active_ip} 3次探测均无响应，已失效或被阻断，准备重新优选..."
                    print(msg)
                    send_tg_msg(msg)
                    need_rescan = True
                    
            if need_rescan:
                best_ip, stats_msg = await scan_warp_ips()
                if best_ip:
                    success, ddns_msg = update_cloudflare_ddns(best_ip)
                    if success:
                        current_active_ip = best_ip
                        force_rescan = False
                    send_tg_msg(f"{stats_msg}\n{ddns_msg}")
                else:
                    print("未找到有效节点，中止本次更新。\n")
                    send_tg_msg(stats_msg)
                    
        except Exception as e:
            err_msg = f"执行周期内发生异常: {e}"
            print(err_msg + "\n")
            send_tg_msg(f"❌ {err_msg}")
            
        print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] 进入休眠，等待 {INTERVAL_MINUTES} 分钟自动执行，或等待 Telegram 手动信号...\n")
        
        try:
            await asyncio.wait_for(trigger_event.wait(), timeout=INTERVAL_MINUTES * 60)
            print(f"\n[{time.strftime('%H:%M:%S')}] ⚡ 接收到手动触发信号，立即中断休眠并强制重新测速！")
            trigger_event.clear()
            force_rescan = True
        except asyncio.TimeoutError:
            force_rescan = False 

if __name__ == "__main__":
    asyncio.run(main_loop())

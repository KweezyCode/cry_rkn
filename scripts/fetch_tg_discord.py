import urllib.request
import json
import ipaddress
import re

TELEGRAM_CIDR_URL = "https://core.telegram.org/resources/cidr.txt"

DISCORD_VOICE_IPS = [
    # Этот список ты можешь пополнять. Это IP-адреса голосовых серверов
    # которые уже есть в Re-filter-lists/discord_ips.lst или из других источников.
    "138.128.140.253", "66.22.206.163", "66.22.206.181",
    "138.128.140.247", "66.22.206.173", "66.22.204.181",
    "66.22.204.183", "66.22.204.171", "66.22.204.178", 
    "66.22.206.35"
]

def fetch_telegram_cidrs():
    print(f"🌐 Скачивание официальных подсетей Telegram из {TELEGRAM_CIDR_URL} ...")
    cidrs = set()
    try:
        req = urllib.request.Request(TELEGRAM_CIDR_URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=10) as response:
            text = response.read().decode('utf-8')
            for line in text.splitlines():
                cidr = line.strip()
                # валидируем что спарсили именно CIDR
                if cidr and '/' in cidr:
                    cidrs.add(cidr)
        print(f"✅ Успешно получено {len(cidrs)} подсетей Telegram.")
    except Exception as e:
        print(f"❌ Ошибка при получении Telegram CIDR: {e}")
    return cidrs

def fetch_discord_cidrs():
    print(f"🌐 Обработка голосовых IP серверов Discord ...")
    cidrs = set()
    for ip in DISCORD_VOICE_IPS:
        ip = ip.strip()
        if ip:
            # Для sing-box и марштутизации один IP указывается как /32 (IPv4) или /128 (IPv6)
            if ':' in ip:
                cidrs.add(f"{ip}/128")
            elif '/' not in ip:
                cidrs.add(f"{ip}/32")
            else:
                cidrs.add(ip)
    print(f"✅ Обработано {len(cidrs)} подсетей/IP Discord.")
    return cidrs

def main():
    import os
    if not os.path.exists('output'): os.makedirs('output')

    tg_cidrs = set(fetch_telegram_cidrs())
    discord_cidrs = set(fetch_discord_cidrs())
    
    # Сортировка
    def sort_key(cidr):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            return (net.version, net.network_address)
        except ValueError:
            return (0, 0)
            
    tg_sorted = sorted(list(tg_cidrs), key=sort_key)
    discord_sorted = sorted(list(discord_cidrs), key=sort_key)
    
    with open('output/custom_telegram-cidr.txt', 'w', encoding='utf-8') as f:
        for c in tg_sorted:
            f.write(c + '\n')
            
    with open('output/custom_discord-voice-cidr.txt', 'w', encoding='utf-8') as f:
        for c in discord_sorted:
            f.write(c + '\n')
            
    print(f"\n📦 Telegram CIDR сохранен: output/custom_telegram-cidr.txt (Всего {len(tg_sorted)} записей)")
    print(f"📦 Discord CIDR сохранен: output/custom_discord-voice-cidr.txt (Всего {len(discord_sorted)} записей)")

if __name__ == "__main__":
    main()

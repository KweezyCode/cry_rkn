import urllib.request
import json
import ipaddress
import re

SOURCE_URL = "https://raw.githubusercontent.com/Runnin4ik/dpi-detector/main/tcp16.json"

def fetch_json(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read().decode('utf-8'))

def fetch_current_asn(ip):
    """Динамически узнаёт актуальную ASN для IP-адреса через RIPE API."""
    url = f"https://stat.ripe.net/data/network-info/data.json?resource={ip}"
    try:
        data = fetch_json(url)
        asns = data.get('data', {}).get('asns', [])
        return [str(asn) for asn in asns]
    except Exception:
        return []

def fetch_prefixes_from_ripe(asn):
    """Получает все анонсируемые IPv4 и IPv6 подсети для переданной ASN."""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}"
    try:
        data = fetch_json(url)
        prefixes = []
        for item in data.get('data', {}).get('prefixes', []):
            prefixes.append(item.get('prefix'))
        return prefixes
    except Exception as e:
        print(f"❌ Ошибка при получении сетей для ASN {asn}: {e}")
        return []

def main():
    print(f"🌐 Скачивание актуального списка серверов из репозитория dpi-detector...")
    try:
        target_data = fetch_json(SOURCE_URL)
        print(f"✅ Успешно загружено {len(target_data)} записей.")
    except Exception as e:
        print(f"❌ Не удалось скачать исходный JSON: {e}")
        return

    asns = set()
    
    print("🔍 Извлечение и проверка автономных систем (ASN)...")
    for item in target_data:
        ip = item.get('ip')
        raw_asn = str(item.get('asn', ''))
        clean_asn = re.sub(r'\D', '', raw_asn) # убираем мусор вроде ☆
        
        if clean_asn:
            asns.add(clean_asn)
        elif ip:
            # Предусмотрена защита на случай, если в JSON не будет поля ASN
            # или если автор забудет его обновить, но укажет IP
            current_asns = fetch_current_asn(ip)
            for a in current_asns:
                asns.add(a)

    print(f"✅ Итого найдено {len(asns)} уникальных ASN: {', '.join(sorted(asns))}")
    
    all_cidrs = set()
    
    # Чтобы не засорять консоль логированием каждого запроса
    print(f"🌐 Идёт загрузка всех CIDR-префиксов по каждой из {len(asns)} ASN. Это займёт около 30 секунд...")
    for i, asn in enumerate(sorted(asns), 1):
        prefixes = fetch_prefixes_from_ripe(asn)
        for p in prefixes:
            all_cidrs.add(p)
            
    # Сортировка результата
    def sort_key(cidr):
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            return (net.version, net.network_address)
        except ValueError:
            return (0, 0)
            
    sorted_cidrs = sorted(list(all_cidrs), key=sort_key)
    
    # Сохраняем файл
    out_file = 'output/custom_asn-16kb-cidr.txt'
    with open(out_file, 'w', encoding='utf-8') as f:
        for c in sorted_cidrs:
            if c:
                f.write(c + '\n')
                
    print(f"✅ Завершено! Успешно собрано {len(sorted_cidrs)} подсетей (IPv4 и IPv6).")
    print(f"📁 Результат обновлен в файле: {out_file}")

if __name__ == "__main__":
    main()

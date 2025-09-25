#!/usr/bin/env python3
import sys
import re
from netaddr import IPSet, IPNetwork, iprange_to_cidrs
import requests

# === Настройки ===
WG_CONFIG_FILE = 'wg1.conf'        # путь к конфигу WireGuard
EXCLUDE_FILE = 'exclude.txt'       # локальные исключения
COUNTRY_CODE = 'RU'                # страна для RIPE
CUTOFF_PREFIX = 16                 # маска для "загрубления" мелких сетей

def read_cidrs_from_file(filepath):
    cidrs = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    cidrs.append(line)
    except FileNotFoundError:
        print(f"⚠️ Файл {filepath} не найден. Продолжаем без локальных исключений.", file=sys.stderr)
    return cidrs

def normalize_ripe_ipv4_list(ipv4_list):
    """
    Преобразует список из RIPE:
    - строки вида "192.0.2.0/24" → оставляем как есть,
    - строки вида "192.0.2.0-192.0.2.255" → преобразуем в CIDR.
    Возвращает список CIDR в виде строк.
    """
    normalized = []
    for item in ipv4_list:
        item = item.strip()
        if '-' in item:
            try:
                start_ip, end_ip = item.split('-')
                # Преобразуем диапазон в CIDR
                cidrs = iprange_to_cidrs(start_ip, end_ip)
                normalized.extend([str(cidr) for cidr in cidrs])
            except Exception as e:
                print(f"⚠️ Не удалось обработать диапазон: {item} ({e})", file=sys.stderr)
        else:
            # Уже CIDR или одиночный IP (например, "192.0.2.1" → станет /32)
            try:
                # netaddr автоматически интерпретирует "1.2.3.4" как /32
                net = IPNetwork(item)
                normalized.append(str(net))
            except Exception as e:
                print(f"⚠️ Некорректная сеть: {item} ({e})", file=sys.stderr)
    return normalized

def get_ripe_country_ipv4(country_code='RU'):
    url = f'https://stat.ripe.net/data/country-resource-list/data.json?resource={country_code}'
    try:
        print(f"📥 Запрашиваю IPv4 ресурсы для страны {country_code} у RIPE...", file=sys.stderr)
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        raw_ipv4_list = data['data']['resources']['ipv4']
        print(f"✅ Получено {len(raw_ipv4_list)} записей от RIPE (до нормализации).", file=sys.stderr)
        normalized = normalize_ripe_ipv4_list(raw_ipv4_list)
        print(f"🔧 После нормализации диапазонов → CIDR: {len(normalized)} префиксов.", file=sys.stderr)
        return normalized
    except Exception as e:
        print(f"❌ Ошибка при получении или обработке данных от RIPE: {e}", file=sys.stderr)
        sys.exit(1)

def expand_small_networks(cidr_list, cutoff_prefix=24):
    """Расширяет только мелкие сети (prefixlen > cutoff) до cutoff_prefix."""
    result = []
    for item in cidr_list:
        try:
            net = IPNetwork(item)
            if net.prefixlen > cutoff_prefix:
                net.prefixlen = cutoff_prefix
                net = net.cidr
            result.append(str(net))
        except Exception as e:
            print(f"⚠️ Пропущена некорректная сеть: {item} ({e})", file=sys.stderr)
    return result

def read_wg_config(filepath):
    try:
        with open(filepath, 'r') as f:
            return f.read()
    except FileNotFoundError:
        print(f"❌ Файл конфигурации {filepath} не найден.", file=sys.stderr)
        sys.exit(1)

def write_wg_config(filepath, content):
    with open(filepath, 'w') as f:
        f.write(content)
    print(f"✅ Файл {filepath} успешно обновлён.", file=sys.stderr)

def main():
    # 1. Локальные исключения — БЕЗ изменений
    local_excludes = read_cidrs_from_file(EXCLUDE_FILE)
    print(f"📁 Локальных исключений (без изменений): {len(local_excludes)}", file=sys.stderr)

    # 2. RIPE-исключения — с обработкой мелких сетей
    ripe_raw = get_ripe_country_ipv4(COUNTRY_CODE)
    ripe_processed = expand_small_networks(ripe_raw, CUTOFF_PREFIX)
    print(f"🌍 RIPE-сетей после агрегации до /{CUTOFF_PREFIX}: {len(ripe_processed)}", file=sys.stderr)

    # 3. Объединяем ВСЕ исключения
    all_excludes = local_excludes + ripe_processed

    # 4. Создаём IPSet (автоматически объединит пересечения)
    try:
        excluded_set = IPSet(all_excludes)
    except Exception as e:
        print(f"❌ Ошибка при создании IPSet: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"🧱 Всего исключений после объединения: {len(excluded_set.iter_cidrs())} CIDR", file=sys.stderr)

    # 5. Вычитаем из полного IPv4
    full_ipv4 = IPSet(['0.0.0.0/0'])
    allowed_ipv4 = full_ipv4 - excluded_set
    allowed_cidrs = [str(cidr) for cidr in allowed_ipv4.iter_cidrs()]

    # 5. Формируем строку AllowedIPs
    allowed_ips_line = 'AllowedIPs = ' + ', '.join(allowed_cidrs)

    # 6. Читаем конфиг
    config_content = read_wg_config(WG_CONFIG_FILE)

    # 7. Заменяем строку AllowedIPs
    # Ищем любую строку, начинающуюся с "AllowedIPs" (с возможными пробелами)
    pattern = r'^(\s*AllowedIPs\s*=\s*).*$'
    if re.search(pattern, config_content, re.MULTILINE):
        new_content = re.sub(pattern, allowed_ips_line, config_content, flags=re.MULTILINE)
    else:
        # Если строка не найдена — добавим в конец секции [Peer]
        # (простой вариант: просто добавим в конец файла)
        new_content = config_content.rstrip() + '\n' + allowed_ips_line + '\n'
        print("⚠️ Строка AllowedIPs не найдена — добавлена в конец файла.", file=sys.stderr)

    # 8. Записываем обратно
    write_wg_config(WG_CONFIG_FILE, new_content)

    # 9. Опционально: выводим количество правил
    print(f"📊 В AllowedIPs добавлено {len(allowed_cidrs)} префиксов.", file=sys.stderr)

if __name__ == '__main__':
    main()
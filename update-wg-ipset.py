#!/usr/bin/env python3
import sys
import re
from netaddr import IPSet, IPNetwork, iprange_to_cidrs
import requests
import subprocess
import os
import shutil

# === Настройки ===
WG_CONFIG_FILE = '/etc/wireguard/wg1.conf'        # путь конфигу WireGuard
WG_INTERFACE = 'wg1'
ETH_INTERFACE = 'ens3'
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
EXCLUDE_FILE = os.path.join(SCRIPT_DIR, 'exclude.txt') # локальные исключения
INCLUDE_FILE = os.path.join(SCRIPT_DIR, 'include.txt') 
COUNTRY_CODE = 'RU'                # страна для RIPE
CUTOFF_PREFIX = 10                 # маска для "загрубления" мелких сетей
IPSET_NAME = 'wg_allowed_ips'      # имя для ipset

def execute_command(cmd, description="", shell=True):
    """Выполняет команду и проверяет результат"""
    try:
        result = subprocess.run(cmd, shell=shell, check=True, capture_output=True, text=True)
        if description:
            print(f"✅ {description}", file=sys.stderr)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка выполнения команды '{cmd}': {e}", file=sys.stderr)
        print(f"stderr: {e.stderr}", file=sys.stderr)
        return None

def read_cidrs_from_file(filepath):
    """Читает CIDR из файла (игнорирует пустые строки и комментарии)."""
    cidrs = []
    if not os.path.exists(filepath):
        print(f"⚠️ Файл {filepath} не найден. Пропускаем.", file=sys.stderr)
        return cidrs
    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    cidrs.append(line)
    except Exception as e:
        print(f"❌ Ошибка чтения {filepath}: {e}", file=sys.stderr)
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
            # Уже CIDR или одиночный IP (например, "1.2.3.4" → станет /32)
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

def check_dependencies():
    """Проверяет наличие необходимых утилит"""
    deps = ['ipset', 'iptables', 'wg']
    missing = []
    
    for dep in deps:
        if not shutil.which(dep):
            missing.append(dep)
    
    if missing:
        print(f"❌ Отсутствующие зависимости: {', '.join(missing)}", file=sys.stderr)
        print("Для работы скрипта установите: ipset, iptables, wireguard-tools", file=sys.stderr)
        sys.exit(1)
    
    print("✅ Все зависимости присутствуют", file=sys.stderr)

def create_ipset(ipset_name):
    """Создает ipset для разрешенных IP-адресов"""
    # Проверяем, существует ли уже ipset
    result = execute_command(f"ipset list {ipset_name}", f"Проверка существования ipset {ipset_name}")
    if result is None:
        # Если не существует, создаем
        execute_command(f"ipset create {ipset_name} hash:net", f"Создание ipset {ipset_name}")
    else:
        print(f"ℹ️ ipset {ipset_name} уже существует", file=sys.stderr)

def flush_ipset(ipset_name):
    """Очищает ipset"""
    execute_command(f"ipset flush {ipset_name}", f"Очистка ipset {ipset_name}")

def add_to_ipset(ipset_name, cidr):
    """Добавляет CIDR в ipset"""
    execute_command(f"ipset add {ipset_name} {cidr}", f"Добавление {cidr} в ipset")

def setup_iptables_rules(wg_interface, ipset_name):
    """Настраивает iptables правила для перенаправления трафика"""
    # Удаляем старые правила, если они есть
    cleanup_iptables_rules(wg_interface, ipset_name)
    
    # Правила для OUTPUT цепочки (исходящий трафик)
    execute_command(f"iptables -A OUTPUT -m set --match-set {ipset_name} dst -o {wg_interface} -j ACCEPT", 
                   f"Настройка OUTPUT правила для {wg_interface}")
    execute_command(f"iptables -A OUTPUT -m set --match-set {ipset_name} dst -j RETURN", 
                   f"Настройка OUTPUT RETURN правила для {wg_interface}")
    
    # Правила для FORWARD цепочки (маршрутизация трафика)
    execute_command(f"iptables -A FORWARD -i {ETH_INTERFACE} -o {wg_interface} -m set --match-set {ipset_name} dst -j ACCEPT", 
                   f"Настройка FORWARD правила для {wg_interface}")
    execute_command(f"iptables -A FORWARD -i {wg_interface} -o {ETH_INTERFACE} -j ACCEPT", 
                   "Настройка обратного FORWARD правила")

def cleanup_iptables_rules(wg_interface, ipset_name):
    """Очищает старые iptables правила"""
    # Удаляем правила для OUTPUT
    try:
        execute_command(f"iptables -D OUTPUT -m set --match-set {ipset_name} dst -o {wg_interface} -j ACCEPT", 
                       f"Удаление старого OUTPUT правила для {wg_interface}")
    except:
        pass
    try:
        execute_command(f"iptables -D OUTPUT -m set --match-set {ipset_name} dst -j RETURN", 
                       "Удаление старого OUTPUT RETURN правила")
    except:
        pass
    
    # Удаляем правила для FORWARD
    try:
        execute_command(f"iptables -D FORWARD -i {ETH_INTERFACE} -o {wg_interface} -m set --match-set {ipset_name} dst -j ACCEPT", 
                       "Удаление старого FORWARD правила")
    except:
        pass
    try:
        execute_command(f"iptables -D FORWARD -i {wg_interface} -o {ETH_INTERFACE} -j ACCEPT", 
                       "Удаление старого обратного FORWARD правила")
    except:
        pass

def update_wireguard_config_for_ipset(config_path):
    """Обновляет конфиг WireGuard для работы с ipset/iptables схемой"""
    try:
        with open(config_path, 'r') as f:
            content = f.read()
        
        # Заменяем или добавляем AllowedIPs с минимальным значением
        # Удаляем существующую строку AllowedIPs
        lines = content.split('\n')
        new_lines = []
        for line in lines:
            if not line.strip().startswith('AllowedIPs'):
                new_lines.append(line)
            else:
                # Добавляем комментарий вместо старой строки
                new_lines.append(f"# {line}  # Закомментировано для использования с ipset/iptables")
        
        # Добавляем новую строку AllowedIPs с минимальным набором
        # Вставляем после секции [Peer]
        modified_content = '\n'.join(new_lines)
        modified_content = re.sub(
            r'(\[Peer\]\s*\n)',
            r'\1AllowedIPs = 0.0.0.0/32\n',  # Пустой маршрут, так как управление через iptables
            modified_content,
            count=1
        )
        
        with open(config_path, 'w') as f:
            f.write(modified_content)
        
        print(f"✅ Конфигурация WireGuard {config_path} обновлена для использования с ipset/iptables", file=sys.stderr)
    except Exception as e:
        print(f"❌ Ошибка обновления конфигурации WireGuard: {e}", file=sys.stderr)
        sys.exit(1)

def save_persistent_config(ipset_name):
    """Сохраняет конфигурацию для восстановления после перезагрузки"""
    try:
        # Проверяем, установлены ли пакеты для постоянства
        if not shutil.which("iptables-save") or not shutil.which("ipset"):
            print("⚠️ Утилиты iptables-save или ipset не найдены. Установите iptables-persistent и ipset.", file=sys.stderr)
            return
        
        # Создаем директории, если не существуют
        os.makedirs("/etc/iptables", exist_ok=True)
        os.makedirs("/etc", exist_ok=True)
        
        # Сохраняем iptables правила
        execute_command("iptables-save > /etc/iptables/rules.v4", "Сохранение правил iptables")
        
        # Сохраняем ipset
        execute_command(f"ipset save {ipset_name} > /etc/ipset.conf", "Сохранение ipset")
        
        print("✅ Конфигурация сохранена для восстановления после перезагрузки", file=sys.stderr)
        print("ℹ️ Установите пакеты iptables-persistent и ipset-persistent для автоматического восстановления", file=sys.stderr)
    except Exception as e:
        print(f"⚠️ Ошибка сохранения конфигурации для перезагрузки: {e}", file=sys.stderr)
        print("После перезагрузки потребуется повторный запуск скрипта", file=sys.stderr)

def main():
    print("🔄 Запуск обновления WireGuard с использованием ipset и iptables", file=sys.stderr)
    
    # Проверяем зависимости
    check_dependencies()
    
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
    full_ipv4 = IPSet(['0.0.0/0'])
    allowed_ipv4 = full_ipv4 - excluded_set

    # 6. ДОБАВЛЯЕМ include.txt (приоритет выше!)
    include_cidrs = read_cidrs_from_file(INCLUDE_FILE)
    if include_cidrs:
        include_set = IPSet(include_cidrs)
        allowed_ipv4 = allowed_ipv4 | include_set  # объединение
        print(f"➕ Добавлено из include.txt: {len(include_set.iter_cidrs())} CIDR", file=sys.stderr)

    # 7. Преобразуем в список
    allowed_cidrs = [str(cidr) for cidr in allowed_ipv4.iter_cidrs()]

    # 8. Создаем или обновляем ipset
    create_ipset(IPSET_NAME)
    flush_ipset(IPSET_NAME)
    
    print(f"🌐 Добавление {len(allowed_cidrs)} CIDR в ipset...", file=sys.stderr)
    for i, cidr in enumerate(allowed_cidrs):
        add_to_ipset(IPSET_NAME, cidr)
        # Показываем прогресс каждые 1000 записей
        if (i + 1) % 1000 == 0:
            print(f" Процесс: {i + 1}/{len(allowed_cidrs)}", file=sys.stderr)

    # 9. Настраиваем iptables правила
    setup_iptables_rules(WG_INTERFACE, IPSET_NAME)

    # 10. Обновляем конфигурацию WireGuard
    update_wireguard_config_for_ipset(WG_CONFIG_FILE)

    # 11. Перезапускаем WireGuard интерфейс для применения изменений в конфиге
    try:
        subprocess.run(['systemctl', 'restart', f'wg-quick@{WG_INTERFACE}'], check=True)
        print(f"🔄 Интерфейс {WG_INTERFACE} перезапущен.", file=sys.stderr)
    except subprocess.CalledProcessError as e:
        print(f"❌ Ошибка перезапуска интерфейса {WG_INTERFACE}: {e}", file=sys.stderr)
        sys.exit(1)

    # 12. Сохраняем конфигурацию для восстановления после перезагрузки
    save_persistent_config(IPSET_NAME)

    print(f"✅ Обновление завершено. Используется ipset {IPSET_NAME} с {len(allowed_cidrs)} CIDR.", file=sys.stderr)
    print(f"📊 Статистика: {len(local_excludes)} локальных исключений, {len(ripe_processed)} RIPE исключений, {len(include_cidrs) if include_cidrs else 0} включений", file=sys.stderr)

if __name__ == '__main__':
    main()
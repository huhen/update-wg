#!/usr/bin/env python3
import subprocess
import sys
import os

def execute_command(cmd, description=""):
    """Выполняет команду и возвращает результат"""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            if description:
                print(f"✅ {description}")
            return result.stdout
        else:
            if description:
                print(f"❌ {description}")
            return None
    except Exception as e:
        print(f"❌ Ошибка выполнения команды '{cmd}': {e}")
        return None

def execute_command_no_check(cmd, description="", shell=True):
    """Выполняет команду без проверки результата (для команд, которые могут завершаться с ошибкой)"""
    try:
        result = subprocess.run(cmd, shell=shell, capture_output=True, text=True)
        if description:
            print(f"✅ {description}", file=sys.stderr)
        return result.stdout, result.returncode
    except Exception as e:
        print(f"⚠️ Ошибка выполнения команды '{cmd}': {e}", file=sys.stderr)
        return None, -1
    
def check_ipset():
    """Проверяет наличие ipset и его содержимое"""
    print("🔍 Проверка ipset...")
    
    # Проверяем, существует ли ipset
    result = execute_command("ipset list wg_allowed_ips", "Проверка существования ipset wg_allowed_ips")
    if result:
        print("✅ ipset wg_allowed_ips существует")
        # Подсчитываем количество записей (ищем строки с содержимым, а не заголовки)
        lines = result.split('\n')
        # Пропускаем заголовочные строки и ищем только те, что содержат IP-адреса
        entries = [line for line in lines if '.' in line and any(c.isdigit() for c in line) and not line.startswith('Name:') and not line.startswith('Type:') and not line.startswith('Revision:') and not line.startswith('Header:') and not line.startswith('Size in memory:') and not line.startswith('References:') and not line.startswith('Number of entries:') and not line.startswith('Members:')]
        print(f"📊 Найдено {len(entries)} записей в ipset")
        
        # Проверяем, содержит ли ipset нужный IP с помощью ipset test
        target_ip = "151.101.194.217"
        test_result = execute_command_no_check(f"ipset test wg_allowed_ips {target_ip}", "")
        if test_result[1] == 0:  # Если код возврата 0, значит IP в ipset
            print(f"✅ Целевой IP {target_ip} присутствует в ipset")
        else:
            print(f"❌ Целевой IP {target_ip} отсутствует в ipset")
            
            # Проверим, может быть IP входит в один из CIDR блоков
            print(f"💡 Проверка, входит ли {target_ip} в один из разрешенных CIDR блоков...")
            for line in entries:
                if line.strip():
                    # Проверим каждый CIDR блок на вхождение IP
                    cidr = line.strip()
                    check_cmd = f"python3 -c \"from netaddr import IPNetwork, IPAddress; print(IPAddress('{target_ip}') in IPNetwork('{cidr}'))\" 2>/dev/null || echo 'need to check manually'"
                    check_result = execute_command_no_check(check_cmd, "")
                    if check_result and "True" in str(check_result[0]):
                        print(f"✅ Целевой IP {target_ip} входит в разрешенный блок {cidr}")
                        break
            else:
                print(f"❌ Целевой IP {target_ip} не входит ни в один разрешенный блок")
    else:
        print("❌ ipset wg_allowed_ips не найден")

def check_iptables():
    """Проверяет iptables правила"""
    print("\n🔍 Проверка iptables правил...")
    
    # Проверяем OUTPUT правила
    result = execute_command("iptables -L OUTPUT -v -n", "Проверка OUTPUT правил")
    if result and "MARK" in result:
        print("✅ Найдены OUTPUT MARK правила")
    else:
        print("❌ OUTPUT MARK правила не найдены")
    
    # Проверяем mangle таблицу
    result = execute_command("iptables -t mangle -L PREROUTING -v -n", "Проверка PREROUTING правил в mangle")
    if result and "MARK" in result:
        print("✅ Найдены PREROUTING MARK правила")
    else:
        print("❌ PREROUTING MARK правила не найдены")

def check_wireguard():
    """Проверяет состояние WireGuard интерфейса"""
    print("\n🔍 Проверка WireGuard интерфейса...")
    
    # Проверяем, запущен ли интерфейс
    result = execute_command("ip link show wg1", "Проверка наличия интерфейса wg1")
    if result:
        print("✅ Интерфейс wg1 существует")
    else:
        print("❌ Интерфейс wg1 не найден")
        return
    
    # Проверяем статус интерфейса
    result = execute_command("ip addr show wg1", "Проверка адреса интерфейса wg1")
    if result:
        print("✅ Интерфейс wg1 активен")
        print(f"   Адреса интерфейса wg1: {result.strip()}")
    else:
        print("❌ Интерфейс wg1 не активен")
    
    # Проверяем статус WireGuard
    result = execute_command("wg show wg1", "Проверка статуса WireGuard")
    if result:
        print("✅ WireGuard wg1 работает")
        print(f"   Статус: {result.strip()}")
    else:
        print("❌ WireGuard wg1 не работает")
    
    # Проверяем конфигурацию WireGuard
    try:
        with open('/etc/wireguard/wg1.conf', 'r') as f:
            content = f.read()
        
        if 'Table = off' in content:
            print("✅ Параметр 'Table = off' установлен в конфигурации wg1")
        else:
            print("❌ Параметр 'Table = off' НЕ установлен в конфигурации wg1")
    except Exception as e:
        print(f"❌ Ошибка чтения конфигурации wg1: {e}")

def check_routing(ip_to_test="151.101.194.217"):
    """Проверяет маршрутизацию для конкретного IP"""
    print(f"\n🔍 Проверка маршрутизации для {ip_to_test}...")
    
    # Проверяем обычный маршрут для целевого IP
    result = execute_command(f"ip route get {ip_to_test}", f"Проверка обычного маршрута для {ip_to_test}")
    if result:
        print(f"✅ Найден обычный маршрут для {ip_to_test}")
        print(f"   Маршрут: {result.strip()}")
        
        # Проверяем, идет ли трафик через wg1 в обычной таблице
        if "wg1" in result:
            print(f"⚠️ Трафик для {ip_to_test} направляется через wg1 в обычной таблице (это неожиданно)")
        else:
            print(f"❌ Трафик для {ip_to_test} НЕ направляется через wg1 в обычной таблице (это нормально)")
    else:
        print(f"❌ Не найден обычный маршрут для {ip_to_test}")
    
    # Проверяем маршрут с использованием fwmark (как если бы трафик был помечен)
    print(f"\n🔍 Проверка маршрута для {ip_to_test} с fwmark 0x1 (как если бы iptables его пометил)...")
    result = execute_command(f"ip route get {ip_to_test} fwmark 0x1", f"Проверка маршрута с fwmark для {ip_to_test}")
    if result:
        print(f"✅ Найден маршрут для {ip_to_test} с fwmark 0x1")
        print(f"   Маршрут: {result.strip()}")
        
        # Проверяем, идет ли трафик через wg1 при наличии fwmark
        if "wg1" in result:
            print(f"✅ Трафик для {ip_to_test} с fwmark 0x1 направляется через wg1")
        else:
            print(f"❌ Трафик для {ip_to_test} с fwmark 0x1 НЕ направляется через wg1")
    else:
        print(f"❌ Не найден маршрут для {ip_to_test} с fwmark 0x1")

def check_kernel_parameters():
    """Проверяет параметры ядра, влияющие на маршрутизацию"""
    print("\n🔍 Проверка параметров ядра...")
    
    # Проверяем IP forwarding
    result = execute_command("cat /proc/sys/net/ipv4/ip_forward", "Проверка IP forwarding")
    if result and result.strip() == "1":
        print("✅ IP forwarding включен")
    else:
        print("❌ IP forwarding выключен (требуется для маршрутизации через wg1)")

def check_policy_routing():
    """Проверяет политику маршрутизации"""
    print("\n🔍 Проверка политики маршрутизации...")
    
    # Проверяем правила политики маршрутизации
    result = execute_command("ip rule show", "Проверка правил политики маршрутизации")
    if result:
        print("✅ Правила политики маршрутизации:")
        print(f"   {result.strip()}")
        
        # Подсчитываем количество правил для fwmark
        lines = result.split('\n')
        fwmark_rules = [line for line in lines if "fwmark 0x1" in line and ("wg1_table" in line or "1000" in line)]
        if len(fwmark_rules) > 0:
            if len(fwmark_rules) == 1:
                print("✅ Найдено 1 правило политики маршрутизации для fwmark 0x1")
            else:
                print(f"⚠️  Найдено {len(fwmark_rules)} дублирующих правила политики маршрутизации для fwmark 0x1")
        else:
            print("❌ Не найдено правила политики маршрутизации для fwmark 0x1")
    else:
        print("❌ Не удалось получить правила политики маршрутизации")
    
    # Проверяем таблицы маршрутов
    result = execute_command("ip route show table wg1_table", "Проверка таблицы маршрутов wg1_table")
    if result:
        print("✅ Найдена таблица маршрутов wg1_table:")
        print(f"   {result.strip()}")
    else:
        print("❌ Таблица маршрутов wg1_table не найдена")
        # Пробуем проверить по числовому ID
        result = execute_command("ip route show table 1000", "Проверка таблицы маршрутов 1000")
        if result:
            print("✅ Найдена таблица маршрутов 1000:")
            print(f"   {result.strip()}")
        else:
            print("❌ Таблица маршрутов 1000 не найдена")
            # Проверим, есть ли вообще какие-то таблицы с этим ID
            result = execute_command("cat /etc/iproute2/rt_tables", "Проверка файла определения таблиц")
            if result and "1000 wg1_table" in result:
                print("✅ Таблица 1000 определена в /etc/iproute2/rt_tables")
            else:
                print("❌ Таблица 1000 не определена в /etc/iproute2/rt_tables")

def check_systemd_service():
    """Проверяет статус systemd сервиса WireGuard"""
    print("\n🔍 Проверка статуса systemd сервиса...")
    
    result = execute_command("systemctl status wg-quick@wg1", "Проверка статуса сервиса wg-quick@wg1")
    if result and "active (exited)" in result:
        print("✅ Сервис wg-quick@wg1 активен")
    else:
        print("❌ Сервис wg-quick@wg1 не активен")

def check_connection_to_target(target_ip="151.101.194.217"):
    """Проверяет соединение с целевым IP"""
    print(f"\n🔍 Проверка соединения с {target_ip}...")
    
    # Проверяем, может ли система установить соединение с целевым IP
    result = execute_command(f"timeout 5 ping -c 1 -W 1 {target_ip}", f"Проверка ping к {target_ip}")
    if result:
        print(f"✅ Успешный ping к {target_ip}")
    else:
        print(f"❌ Не удалось выполнить ping к {target_ip}")

def main():
    print("🔬 Диагностика маршрутизации трафика через WireGuard")
    print("="*50)
    
    check_ipset()
    check_iptables()
    check_wireguard()
    check_routing()
    check_kernel_parameters()
    check_policy_routing()
    check_systemd_service()
    check_connection_to_target()
    
    print("\n" + "="*50)
    print("📋 Рекомендации:")
    print("1. Убедитесь, что целевой IP присутствует в ipset wg_allowed_ips")
    print("2. Проверьте, что iptables MARK правила корректно настроены")
    print("3. Убедитесь, что правило политики маршрутизации (ip rule) существует")
    print("4. Проверьте, что таблица маршрутов 1000 (wg1_table) существует")
    print("5. Убедитесь, что маршрут по умолчанию в таблице 1000 ведет через wg1")
    print("6. Убедитесь, что интерфейс wg1 активен и подключен")
    print("7. Проверьте, что включен IP forwarding в системе")
    print("\n💡 Для диагностики трафика используйте: tcpdump -i wg1 -n")
    print("💡 Для проверки маркировки трафика: iptables -t mangle -L -v -n")

if __name__ == '__main__':
    main()
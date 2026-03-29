import argparse
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Словарь известных портов и протоколов
PORT_PROTOCOLS = {
    20: 'FTP-data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
    53: 'DNS', 80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-alt'
}

# Сигнатуры для распознавания протоколов по баннеру
BANNER_SIGNATURES = {
    21: [(b'220', 'FTP')],
    22: [(b'SSH', 'SSH')],
    25: [(b'220', 'SMTP')],
    53: [(b'', 'DNS')],
    80: [(b'HTTP', 'HTTP'), (b'html', 'HTTP')],
    110: [(b'+OK', 'POP3'), (b'-ERR', 'POP3')],
    143: [(b'* OK', 'IMAP'), (b'OK', 'IMAP')],
    123: [(b'\x1b', 'NTP')],
    443: [(b'HTTP', 'HTTPS')],
}


def get_protocol_by_banner(port, banner):
    """Определяет протокол по баннеру"""
    if port in BANNER_SIGNATURES:
        for signature, protocol in BANNER_SIGNATURES[port]:
            if signature in banner:
                return protocol
    return None


def scan_tcp_port(host, port, timeout=2):
    """Сканирует TCP порт и определяет протокол"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        start_time = time.time()
        result = sock.connect_ex((host, port))

        if result == 0:
            protocol = None

            # Пытаемся получить баннер
            try:
                # Отправляем соответствующий запрос в зависимости от порта
                if port == 80 or port == 443 or port == 8080:
                    sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                elif port == 21:
                    sock.send(b'NOOP\r\n')
                elif port == 25:
                    sock.send(b'EHLO test\r\n')
                elif port == 110:
                    sock.send(b'CAPA\r\n')
                elif port == 143:
                    sock.send(b'CAPABILITY\r\n')
                elif port == 22:
                    sock.send(b'\r\n')
                else:
                    sock.send(b'\r\n')

                sock.settimeout(1)
                data = sock.recv(1024)

                # Определяем протокол по баннеру
                protocol = get_protocol_by_banner(port, data)

                # Специальная обработка для DNS
                if port == 53 and not protocol:
                    protocol = 'DNS'

            except socket.timeout:
                pass
            except Exception:
                pass

            # Если не распознали, используем известный порт
            if not protocol and port in PORT_PROTOCOLS:
                protocol = PORT_PROTOCOLS[port]

            sock.close()
            return port, protocol, time.time() - start_time
        else:
            sock.close()
            return None
    except socket.error:
        return None
    except Exception:
        return None


def scan_udp_port(host, port, timeout=2):
    """Сканирует UDP порт"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)

        # Отправляем специфичные запросы для разных протоколов
        message = b''
        if port == 53:  # DNS
            # DNS запрос для version.bind
            message = b'\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03'
        elif port == 123:  # NTP
            message = b'\x1b' + 47 * b'\x00'
        elif port == 161:  # SNMP
            message = b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x02\x1f\x40\x02\x01\x00\x02\x01\x00\x30\x0d\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x05\x00'

        sock.sendto(message, (host, port))

        try:
            data, addr = sock.recvfrom(1024)
            protocol = None

            # Распознавание по ответу
            if port == 53 and data:
                protocol = 'DNS'
            elif port == 123 and data and len(data) > 0:
                protocol = 'NTP'
            elif port in PORT_PROTOCOLS:
                protocol = PORT_PROTOCOLS[port]

            sock.close()
            return port, protocol, time.time()
        except socket.timeout:
            # UDP порт может быть открыт, но не отвечать
            sock.close()
            if port in PORT_PROTOCOLS:
                return port, PORT_PROTOCOLS[port], time.time()
            return None
        except:
            sock.close()
            return None
    except PermissionError:
        print(f"Предупреждение: недостаточно прав для UDP порта {port} (запустите с правами администратора)")
        return None
    except socket.error:
        return None
    except Exception:
        return None


def scan_ports(host, start_port, count, scan_tcp=True, scan_udp=True, max_workers=200):
    """Многопоточное сканирование портов"""
    end_port = start_port + count
    results = {'TCP': [], 'UDP': []}

    if scan_tcp:
        print(f"\nСканирование TCP портов {start_port}-{end_port - 1} на {host}...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_tcp_port, host, port): port
                       for port in range(start_port, end_port)}

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    print(f"   Прогресс TCP: {completed}/{count} портов", end='\r')

                result = future.result()
                if result:
                    port, protocol, _ = result
                    results['TCP'].append((port, protocol))

        print(f"\n   TCP сканирование завершено. Найдено открытых портов: {len(results['TCP'])}")

    if scan_udp:
        print(f"\nСканирование UDP портов {start_port}-{end_port - 1} на {host}...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(scan_udp_port, host, port): port
                       for port in range(start_port, end_port)}

            completed = 0
            for future in as_completed(futures):
                completed += 1
                if completed % 50 == 0:
                    print(f"   Прогресс UDP: {completed}/{count} портов", end='\r')

                result = future.result()
                if result:
                    port, protocol, _ = result
                    results['UDP'].append((port, protocol))

        print(f"\n   UDP сканирование завершено. Найдено открытых портов: {len(results['UDP'])}")

    return results


def main():
    parser = argparse.ArgumentParser(description='TCP/UDP Port Scanner')
    parser.add_argument('--tcp', '-t', action='store_true', help='Сканировать TCP порты')
    parser.add_argument('--udp', '-u', action='store_true', help='Сканировать UDP порты')
    parser.add_argument('--start', type=int, required=True, help='Начальное значение диапазона портов')
    parser.add_argument('--count', type=int, required=True, help='Количество исследуемых портов')
    parser.add_argument('host', help='IP-адрес или DNS-имя удалённого хоста')

    args = parser.parse_args()

    # Если не указаны ни TCP, ни UDP, сканируем оба
    scan_tcp = args.tcp or not (args.tcp or args.udp)
    scan_udp = args.udp or not (args.tcp or args.udp)

    # Преобразуем DNS имя в IP
    try:
        host_ip = socket.gethostbyname(args.host)
        print(f"\nСканирование хоста: {args.host} ({host_ip})")
    except socket.gaierror:
        print(f"Ошибка: не удалось разрешить DNS имя '{args.host}'")
        return

    # Проверка валидности параметров
    if args.start < 0 or args.start > 65535:
        print("Ошибка: начальный порт должен быть в диапазоне 0-65535")
        return

    if args.count <= 0 or args.start + args.count > 65536:
        print("Ошибка: неверное количество портов или выход за пределы диапазона")
        return

    # Запуск сканирования
    start_time = time.time()
    results = scan_ports(host_ip, args.start, args.count, scan_tcp, scan_udp)
    elapsed_time = time.time() - start_time

    # Вывод результатов
    print(f"РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ (время: {elapsed_time:.2f} сек)")

    found_any = False

    for protocol_type in ['TCP', 'UDP']:
        if results[protocol_type]:
            found_any = True
            print(f"\n{protocol_type} порты:")
            for port, proto in sorted(results[protocol_type]):
                if proto:
                    print(f"  {protocol_type} {port} {proto}")
                else:
                    print(f"  {protocol_type} {port}")

    if not found_any:
        print("\nОткрытых портов не найдено!")


if __name__ == "__main__":
    main()
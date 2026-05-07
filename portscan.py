import socket
import argparse
import sys
import threading
import time
import random
import struct

PROBES = {
    'HTTP': b'HEAD / HTTP/1.0\r\nHost: test\r\n\r\n',
    'SMTP': b'EHLO test\r\n',
    'POP3': b'CAPA\r\n',
    'IMAP': b'CAPABILITY\r\n',
    'NTP': b'\x1b' + 47 * b'\0',
    'SNMP': b'\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x02\x1f\x40\x02\x01\x00\x02\x01\x00\x30\x0d\x30\x0b\x06\x07\x2b\x06\x01\x02\x01\x01\x01\x05\x00',
}


def create_dns_query(domain="google.com"):
    """Создает DNS запрос"""
    transaction_id = random.randint(0, 65535)
    flags = 0x0100
    questions = 1
    header = struct.pack('!HHHHHH', transaction_id, flags, questions, 0, 0, 0)

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode()
    qname += b'\x00'

    question = qname + struct.pack('!HH', 1, 1)  # Type A, Class IN
    return header + question


def check_tcp_protocol(data):
    """Определяет протокол TCP по ответу"""
    if not data:
        return ""

    try:
        text = data.decode('utf-8', errors='ignore').upper()
    except:
        return ""

    if any(x in text for x in ['HTTP/', 'HTTP/1', '200 OK', '404']):
        return 'HTTP'
    if any(x in text for x in ['220 ', '250 ', 'SMTP', 'ESMTP']):
        return 'SMTP'
    if any(x in text for x in ['+OK', '-ERR', 'POP3']):
        return 'POP3'
    if any(x in text for x in ['* OK', ' OK ', 'IMAP', 'CAPABILITY']):
        return 'IMAP'
    if 'SSH-' in text:
        return 'SSH'
    if '220-' in text or 'FTP' in text:
        return 'FTP'

    return ""


def check_udp_protocol(data):
    """Определяет протокол UDP по ответу"""
    if not data:
        return ""

    if len(data) >= 1 and data[0] == 0x1b:
        return 'NTP'

    if len(data) >= 12 and (data[2] & 0x80):
        return 'DNS'

    if len(data) >= 2 and data[0] == 0x30:
        return 'SNMP'

    return ""


def scan_tcp(host, port):
    """Сканирование TCP порта"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.5)

        if sock.connect_ex((host, port)) == 0:
            protocol = ""

            # Сначала пробуем прочитать баннер
            try:
                sock.settimeout(1)
                data = sock.recv(1024)
                protocol = check_tcp_protocol(data)
            except:
                pass

            # Если нет, отправляем probes
            if not protocol:
                for name in ['HTTP', 'SMTP', 'POP3', 'IMAP']:
                    try:
                        sock.send(PROBES[name])
                        sock.settimeout(1)
                        data = sock.recv(1024)
                        protocol = check_tcp_protocol(data)
                        if protocol:
                            break
                    except:
                        continue

            if protocol:
                print(f"TCP {port} {protocol}")
            else:
                print(f"TCP {port}")

        sock.close()
    except Exception as e:
        pass


def scan_udp(host, port):
    """Сканирование UDP порта"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.5)

        # Отправляем запрос в зависимости от порта
        if port == 53:
            sock.sendto(create_dns_query(), (host, port))
        elif port == 123:
            sock.sendto(PROBES['NTP'], (host, port))
        elif port == 161:
            sock.sendto(PROBES['SNMP'], (host, port))
        else:
            sock.sendto(b'\r\n', (host, port))

        try:
            data, _ = sock.recvfrom(1024)
            protocol = check_udp_protocol(data)
            if protocol:
                print(f"UDP {port} {protocol}")
            else:
                print(f"UDP {port}")
        except socket.timeout:
            pass

        sock.close()
    except Exception:
        pass


def main():
    parser = argparse.ArgumentParser(description='Сканер портов TCP/UDP')
    parser.add_argument('host', help='IP-адрес или доменное имя')
    parser.add_argument('-t', '--tcp', action='store_true', help='Сканировать TCP')
    parser.add_argument('-u', '--udp', action='store_true', help='Сканировать UDP')
    parser.add_argument('--start', type=int, default=1, help='Начальный порт (по умолч: 1)')
    parser.add_argument('--count', type=int, default=100, help='Количество портов (по умолч: 100)')
    parser.add_argument('--threads', type=int, default=50, help='Количество потоков (по умолч: 50)')

    args = parser.parse_args()

    # Если не указаны флаги - сканируем TCP
    if not args.tcp and not args.udp:
        args.tcp = True

    # Проверка портов
    if args.start < 0 or args.start > 65535:
        print("Ошибка: порт должен быть 0-65535")
        return

    if args.count <= 0 or args.start + args.count > 65536:
        print("Ошибка: неверное количество портов")
        return

    # Получаем IP
    try:
        ip = socket.gethostbyname(args.host)
        print(f"\n[*] Сканирование: {args.host} ({ip})")
        print(f" Порты: {args.start}-{args.start + args.count - 1}")
    except socket.gaierror:
        print(f"Ошибка: не могу разрешить '{args.host}'")
        return

    start_time = time.time()
    threads = []
    end_port = args.start + args.count

    # Запускаем сканирование
    for port in range(args.start, end_port):
        if args.tcp:
            t = threading.Thread(target=scan_tcp, args=(ip, port))
            threads.append(t)
            t.start()

        if args.udp:
            t = threading.Thread(target=scan_udp, args=(ip, port))
            threads.append(t)
            t.start()

        # Ограничиваем количество потоков
        if len(threads) >= args.threads:
            for t in threads:
                t.join()
            threads = []

    # Ждем завершения всех потоков
    for t in threads:
        t.join()

    elapsed = time.time() - start_time
    print(f"\n Время: {elapsed:.2f} сек")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Прервано пользователем")
        sys.exit(0)
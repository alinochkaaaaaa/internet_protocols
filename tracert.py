#!/usr/bin/env python3
import socket
import ipaddress
import struct
import time
import sys


def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False


def get_whois_info(ip):
    if is_private_ip(ip):
        return "local", None, None

    try:
        whois_servers = [
            ("whois.iana.org", 43),
            ("whois.ripe.net", 43)
        ]

        netname = None
        as_number = None
        country = None

        for server_addr, port in whois_servers:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((server_addr, port))

                # WHOIS запрос - IP + \r\n, encode() преобразует в байты
                request = f"{ip}\r\n".encode()
                sock.send(request)

                response = b""
                while True:
                    data = sock.recv(4096)
                    if not data:
                        break
                    response += data

                sock.close()
                # декодируем байты, игнорирование ошибок
                response = response.decode('utf-8', errors='ignore')

                for line in response.split('\n'):
                    line = line.strip()
                    if line.startswith('netname:') or line.startswith('NetName:'):
                        netname = line.split(':')[1].strip()
                        if '#' in netname:
                            netname = netname.split('#')[0].strip()
                    elif 'AS' in line and ('origin:' in line.lower() or 'aut-num:' in line.lower()):
                        parts = line.split()
                        for part in parts:
                            if part.startswith('AS'):
                                as_number = part.strip()
                                if '#' in as_number:
                                    as_number = as_number.split('#')[0].strip()
                                break
                    elif line.startswith('country:') or line.startswith('Country:'):
                        country = line.split(':')[1].strip().upper()
                        if '#' in country:
                            country = country.split('#')[0].strip()

                # нашли инф
                if netname or as_number or country:
                    break

            # если сервер не ответил
            except:
                continue

        return netname, as_number, country

    except:
        return None, None, None


def calculate_checksum(data):
    """Расчет контрольной суммы ICMP пакета"""

    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        # Объединяем два байта в одно 16-битное число
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # Инвертируем все биты (~) и оставляем только 16 бит (& 0xFFFF)
    return ~checksum & 0xFFFF


def create_icmp_packet(icmp_id, icmp_sequence):
    icmp_type = 8  # Echo Request
    icmp_code = 0

    # Заголовок без контрольной суммы
    # ! - сетевой порядок байт (big-endian)
    # B - unsigned char (1 байт) - для type и code
    # H - unsigned short (2 байта) - для checksum, id, sequence

    header = struct.pack('!BBHHH', icmp_type, icmp_code, 0, icmp_id, icmp_sequence)

    # Данные с временной меткой
    # '!d' - double (8 байт) в сетевом порядке
    data = struct.pack('!d', time.time())

    packet = header + data
    checksum = calculate_checksum(packet)
    header = struct.pack('!BBHHH', icmp_type, icmp_code, checksum, icmp_id, icmp_sequence)

    return header + data


def traceroute(destination):
    try:
        dest_ip = socket.gethostbyname(destination)
        print(f"Трассировка маршрута к {destination} [{dest_ip}]")
        print()
    except socket.gaierror:
        print(f"{destination} is invalid")
        return

    # права администратора
    try:
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        test_socket.close()
    except PermissionError:
        print("ОШИБКА: Недостаточно прав. Запустите от имени администратора!")
        return

    try:
        # СОЗДАЕМ СОКЕТ
        icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        ttl = 1
        max_ttl = 30
        hop_number = 1
        reached = False
        last_ip = None  # отслеживание последнего IP

        while ttl <= max_ttl and not reached:
            try:
                # TTL
                icmp_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                icmp_socket.settimeout(2)

                # Отправляем пакет
                packet = create_icmp_packet(12345, ttl)
                icmp_socket.sendto(packet, (dest_ip, 0))

                try:
                    # Ждем ответ
                    data, addr = icmp_socket.recvfrom(1024)

                    # Получаем IP отправителя
                    hop_ip = addr[0]

                    # НОВЫЙ УЗЕЛ
                    if hop_ip != last_ip:
                        print(f"{hop_number}. {hop_ip}")

                        # Получаем WHOIS информацию
                        netname, as_number, country = get_whois_info(hop_ip)

                        second_line_parts = []
                        if netname:
                            second_line_parts.append(netname)
                        if as_number:
                            second_line_parts.append(as_number)
                        if country:
                            second_line_parts.append(country)

                        if second_line_parts:
                            print(f"{', '.join(second_line_parts)}")
                        elif is_private_ip(hop_ip):
                            print("local")

                        print()

                        last_ip = hop_ip
                        hop_number += 1

                        if hop_ip == dest_ip:
                            reached = True

                except socket.timeout:
                    # Таймаут - узел не ответил
                    print(f"{hop_number}. *")
                    print()
                    last_ip = None
                    hop_number += 1

                ttl += 1

            except Exception as e:
                print(f"Ошибка при TTL={ttl}: {e}")
                ttl += 1

        icmp_socket.close()
        print("Трассировка завершена")

    except: print("error without traceroute")

def main():
    if len(sys.argv) != 2:
        print("Использование: python tracert.py <IP-адрес или домен>")
        print("Пример: python tracert.py yandex.com")
        sys.exit(1)

    traceroute(sys.argv[1])


if __name__ == "__main__":
    main()
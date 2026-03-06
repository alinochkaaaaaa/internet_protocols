#!/usr/bin/env python3
import socket
import ipaddress
import subprocess
import re
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
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("whois.ripe.net", 43))

        request = f"{ip}\r\n".encode()
        sock.send(request)

        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()
        response = response.decode('utf-8', errors='ignore')

        netname = None
        as_number = None
        country = None

        for line in response.split('\n'):
            line = line.strip()
            if line.startswith('netname:') or line.startswith('NetName:'):
                netname = line.split(':')[1].strip()
            elif 'AS' in line and ('origin:' in line.lower() or 'aut-num:' in line.lower()):
                parts = line.split()
                for part in parts:
                    if part.startswith('AS'):
                        as_number = part.strip()
                        break
            elif line.startswith('country:') or line.startswith('Country:'):
                country = line.split(':')[1].strip().upper()

        return netname, as_number, country

    except:
        return None, None, None


def traceroute(destination):
    try:
        dest_ip = socket.gethostbyname(destination)
        print(f"Трассировка маршрута к {destination} [{dest_ip}]")

    except socket.gaierror:
        print(f"{destination} is invalid")
        return

    try:
        result = subprocess.run(
            ['tracert', '-h', '30', '-w', '1000', '-4', dest_ip],
            capture_output=True,
            text=True,
            encoding='cp866'
        )

        lines = result.stdout.split('\n')
        hop_number = 1

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if (line.startswith('Трассировка') or
                    'с максимальным числом' in line):
                continue

            if '* * *' in line:
                print(f"{hop_number}. *")
                print()
                hop_number += 1
                continue

            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)

            if ip_match:
                ip = ip_match.group(1)
                print(f"{hop_number}. {ip}")

                netname, as_number, country = get_whois_info(ip)

                second_line_parts = []
                if netname:
                    second_line_parts.append(netname)
                if as_number:
                    second_line_parts.append(as_number)
                if country:
                    second_line_parts.append(country)

                if second_line_parts:
                    print(f"{', '.join(second_line_parts)}")
                elif is_private_ip(ip):
                    print("local")
                else:
                    print()

                print()
                hop_number += 1

    except Exception as e:
        print(f"Ошибка: {e}")


def main():
    if len(sys.argv) != 2:
        print("Использование: python tracert.py <IP-адрес или домен>")
        sys.exit(1)

    traceroute(sys.argv[1])


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import socket #создание сокетов, DNS-запросы, WHOIS
import ipaddress # проверка на private/public
import subprocess # запуск внешних программ (tracert)
import re
import sys


def is_private_ip(ip):
    """
    Проверяет, является ли ip адрес local
    Принимает ip адрес и возвращает true если local
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except:
        return False


def get_whois_info(ip):
    """
    Получает информацию WHOIS для ip адреса
    Принимает строку с ip адресом
    Возвращает кортеж (netname, as_number, country)
    """
    if is_private_ip(ip):
        return "local", None, None

    try:
        # tcp
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(("whois.ripe.net", 43))

        # WHOIS запрос - ip адрес + \r\n, encode() - byte
        request = f"{ip}\r\n".encode()
        sock.send(request)

        # пустая строка для накопления ответа
        response = b""
        while True:
            data = sock.recv(4096)
            if not data:
                break
            response += data

        sock.close()

        # Декодируем байты в UTF-8 строку
        # errors='ignore' - пропускаем символы, которые не удалось декодировать
        response = response.decode('utf-8', errors='ignore')

        netname = None
        as_number = None
        country = None

        for line in response.split('\n'):
            line = line.strip() # удаление пробелов в начале и в конце
            # поиск имени сети
            if line.startswith('netname:') or line.startswith('NetName:'):
                netname = line.split(':')[1].strip() # берем вторую часть, те само имя
            # поиск номера автономной системы
            elif 'AS' in line and ('origin:' in line.lower() or 'aut-num:' in line.lower()):
                parts = line.split()
                for part in parts:
                    if part.startswith('AS'):
                        as_number = part.strip() # найденные AS номер
                        break
            # поиск страны
            elif line.startswith('country:') or line.startswith('Country:'):
                country = line.split(':')[1].strip().upper()

        return netname, as_number, country

    except:
        return None, None, None


def traceroute(destination):
    """
    Функция трассировки
    Принимает доменное имя или ip адрес назначения
    Выводит результат трассировки в нужном формате
    """

    try:
        # преобразование имени в ip с пом. dns запроса
        dest_ip = socket.gethostbyname(destination)
        print(f"Трассировка маршрута к {destination} [{dest_ip}]")

    # gaierror - Get Addr Info error, если домаенного имени не существует
    except socket.gaierror:
        print(f"{destination} is invalid")
        return

    try:
        # -h 30    : максимальное количество прыжков (hops) = 30
        # -w 1000  : таймаут ожидания ответа 1000 мс (1 секунда)
        # -4       : принудительно использовать IPv4
        result = subprocess.run(
            ['tracert', '-h', '30', '-w', '1000', '-4', dest_ip],
            capture_output=True,
            text=True,
            encoding='cp866'
        )

        # result.stdout - весь вывод программы tracert
        lines = result.stdout.split('\n')
        hop_number = 1

        for line in lines:
            line = line.strip()
            # убираем пустые строки
            if not line:
                continue

            # пропускаем информационные строки
            if (line.startswith('Трассировка') or
                    'с максимальным числом' in line):
                continue

            # Проверяем на звездочки (таймаут)
            if '* * *' in line:
                print(f"{hop_number}. *")
                print()
                hop_number += 1
                continue

            # IPv4 адрес
            # \d{1,3} - от 1 до 3 цифр
            # \. - точка (экранированная)
            ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)

            if ip_match:
                ip = ip_match.group(1)
                print(f"{hop_number}. {ip}")

                netname, as_number, country = get_whois_info(ip)

                # добавляем информация из WHOIS
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

                print()  # Пустая строка между hops
                hop_number += 1

    except Exception as e:
        print(f"Ошибка: {e}")


def main():
    if len(sys.argv) != 2:
        print("Использование: python tracert.py <IP-адрес или домен>")
        sys.exit(1) # код ошибки при неправильном использовании

    traceroute(sys.argv[1])


if __name__ == "__main__":
    main()
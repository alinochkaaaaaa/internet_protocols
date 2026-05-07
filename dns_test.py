import socket
import struct


def send_query(domain, qtype, qtype_name):
    """Отправка DNS запроса"""
    labels = domain.split('.')
    name_bytes = b''
    for label in labels:
        name_bytes += bytes([len(label)]) + label.encode()
    name_bytes += b'\x00'

    header = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    query = header + name_bytes + struct.pack('!H', qtype) + b'\x00\x01'

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    print(f"Запрос: {qtype_name} {domain}")
    sock.sendto(query, ('127.0.0.1', 53))

    try:
        response, _ = sock.recvfrom(512)
        flags = (response[2] << 8) | response[3]
        ancount = struct.unpack('!H', response[6:8])[0]
        rcode = flags & 0x000F

        if rcode == 0 and ancount > 0:
            return True
        elif rcode == 0:
            print(f"Нет записей")
            return False
        else:
            print(f"Ошибка RCODE={rcode}")
            return False
    except socket.timeout:
        print(f"Таймаут")
        return False
    finally:
        sock.close()


print("ПЕРВЫЙ ЗАПУСК - запросы к форвардеру")

tests = [
    ('urfu.ru', 1, 'A'),
    ('urfu.ru', 2, 'NS'),
    ('docs.google.com', 5, 'CNAME'),
    ('urfu.ru', 6, 'SOA'),
    ('8.8.8.8.in-addr.arpa', 12, 'PTR'),
    ('yandex.ru', 15, 'MX'),
    ('youtube.com', 28, 'AAAA'),
]

for domain, qtype, name in tests:
    send_query(domain, qtype, name)

input("\n Enter для второго запуска")

print("ВТОРОЙ ЗАПУСК - кэш")

for domain, qtype, name in tests:
    send_query(domain, qtype, name)

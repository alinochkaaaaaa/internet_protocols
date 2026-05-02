import socket
import struct


def build_query(domain, qtype):
    """Создание DNS запроса для указанного типа"""
    qtype_bytes = struct.pack('!H', qtype)

    # Кодируем имя
    labels = domain.split('.')
    name_bytes = b''
    for label in labels:
        name_bytes += bytes([len(label)]) + label.encode()
    name_bytes += b'\x00'

    # Заголовок
    header = bytes([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    return header + name_bytes + qtype_bytes + b'\x00\x01'


def send_query(domain, qtype, qtype_name):
    """Отправка запроса и получение ответа"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    query = build_query(domain, qtype)
    sock.sendto(query, ('127.0.0.1', 53))

    try:
        response, _ = sock.recvfrom(512)
        flags = (response[2] << 8) | response[3]
        rcode = flags & 0x000F

        if rcode == 0:
            print(f"{qtype_name}: Успешно")
        else:
            print(f"{qtype_name}: Ошибка (RCODE={rcode})")
    except socket.timeout:
        print(f"{qtype_name}: Таймаут")
    finally:
        sock.close()


# Тестируем все типы
types = [
    (1, 'A'),
    (2, 'NS'),
    (5, 'CNAME'),
    (6, 'SOA'),
    (12, 'PTR'),
    (13, 'HINFO'),
    (15, 'MX'),
    (28, 'AAAA')
]

print("Тестирование различных типов DNS запросов:")
print("=" * 50)

for qtype, name in types:
    send_query('urfu.ru', qtype, name)
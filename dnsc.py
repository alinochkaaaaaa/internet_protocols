import socket
import struct
import sys
import time

# Кэш: (домен, тип, класс) -> (данные, время_истечения)
cache = {}

# Типы DNS записей
TYPE_NAMES = {
    1: 'A',  # IPv4
    2: 'NS',  # Name Server
    5: 'CNAME',  # Canonical Name
    6: 'SOA',  # Start of Authority (информация о зоне)
    12: 'PTR',  # Pointer (для обратных запросов)
    13: 'HINFO',  # Host Information
    15: 'MX',  # Mail Exchange
    28: 'AAAA'  # IPv6
}


def parse_dns_name(data, offset):
    """Преобразует DNS-имя из бинарного формата в строку"""
    labels = []  # Список для частей имени
    pos = offset
    jumped = False  # Флаг, был ли прыжок по компрессии
    original_pos = pos

    while True:
        if pos >= len(data):
            return None, pos

        length = data[pos]

        if length == 0:
            pos += 1
            break

        # Компрессия (0xC0)
        if length & 0xC0:
            if not jumped:
                original_pos = pos + 2
            # Вычисляем смещение
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            pos = pointer
            jumped = True
            continue

        # Обычная метка
        pos += 1
        if pos + length > len(data):
            return None, pos

        label = data[pos:pos + length].decode('ascii')
        labels.append(label)
        pos += length

    if jumped:
        pos = original_pos

    return '.'.join(labels), pos


def encode_dns_name(name):
    """Кодирование DNS имени"""
    parts = name.split('.')
    result = b''
    for part in parts:
        result += bytes([len(part)]) + part.encode('ascii')
    result += b'\x00'
    return result


def build_response(query, answers):
    """Сборка DNS ответа для любого типа записей"""
    tid = query[:2]  # ID транзакции из запроса
    header = tid + b'\x81\x80' + b'\x00\x01' + struct.pack('!H', len(answers)) + b'\x00\x00\x00\x00'
    # 0x8180 = QR=1, Opcode=0, AA=0, TC=0, RD=0, RA=0, RCODE=0

    # Извлекаем вопрос из запроса
    pos = 12
    qname, pos = parse_dns_name(query, pos)
    qtype = struct.unpack('!H', query[pos:pos + 2])[0]
    qclass = struct.unpack('!H', query[pos + 2:pos + 4])[0]
    question = query[12:pos + 4]

    # Секция ответов
    answer_section = b''
    for rname, rtype, ttl, rdata in answers:
        answer_section += b'\xc0\x0c'  # Указатель на имя
        answer_section += struct.pack('!H', rtype)  # Тип
        answer_section += struct.pack('!H', qclass)  # Класс
        answer_section += struct.pack('!I', ttl)   # TTL
        answer_section += struct.pack('!H', len(rdata))  # Длина данных
        answer_section += rdata

    return header + question + answer_section


def parse_rdata(response, offset, rtype, rdlength):
    """Парсинг RDATA в зависимости от типа записи"""
    if rtype == 1:  # A - IPv4
        return response[offset:offset + rdlength]
    elif rtype == 2:  # NS - Name Server
        name, _ = parse_dns_name(response, offset)
        return encode_dns_name(name)
    elif rtype == 5:  # CNAME - Canonical Name
        name, _ = parse_dns_name(response, offset)
        return encode_dns_name(name)
    elif rtype == 6:  # SOA - Start of Authority
        return response[offset:offset + rdlength]
    elif rtype == 12:  # PTR - Pointer
        name, _ = parse_dns_name(response, offset)
        return encode_dns_name(name)
    elif rtype == 15:  # MX - Mail Exchange
        return response[offset:offset + rdlength]
    elif rtype == 28:  # AAAA - IPv6
        return response[offset:offset + rdlength]
    else:
        return response[offset:offset + rdlength]


def main():
    port = 53
    forwarder = ('8.8.8.8', 53)

    # Парсинг аргументов командной строки
    i = 1
    while i < len(sys.argv):
        if sys.argv[i] == '-p' and i + 1 < len(sys.argv):
            port = int(sys.argv[i + 1])
            i += 2
        elif sys.argv[i] == '-f' and i + 1 < len(sys.argv):
            fwd = sys.argv[i + 1]
            if ':' in fwd:
                host, p = fwd.split(':')
                forwarder = (host, int(p))
            else:
                forwarder = (fwd, 53)
            i += 2
        else:
            i += 1

    # Создание UDP сокета
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))

    print(f"DNS Server on port {port}, forwarder {forwarder[0]}:{forwarder[1]}")
    print(f"Supported types: {', '.join(TYPE_NAMES.values())}")

    # Основной цикл обработки запросов
    while True:
        try:
            data, addr = sock.recvfrom(512)

            # Парсинг DNS запроса
            pos = 12
            qname, pos = parse_dns_name(data, pos)

            if not qname:
                continue

            qtype = struct.unpack('!H', data[pos:pos + 2])[0]
            qclass = struct.unpack('!H', data[pos + 2:pos + 4])[0]
            qtype_name = TYPE_NAMES.get(qtype, f"TYPE{qtype}")

            # Проверка кэша
            cache_key = (qname, qtype, qclass)
            if cache_key in cache:
                rdata, expiry = cache[cache_key]
                if time.time() < expiry:
                    ttl = int(expiry - time.time())
                    answers = [(qname, qtype, ttl, rdata)]
                    response = build_response(data, answers)
                    sock.sendto(response, addr)
                    print(f"{addr[0]}, {qtype_name}, {qname}, cache")
                    continue

            # Пересылка запроса форвардеру
            print(f"{addr[0]}, {qtype_name}, {qname}, forwarder")

            fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            fwd.settimeout(5)

            try:
                fwd.sendto(data, forwarder)
                response, _ = fwd.recvfrom(512)

                # Парсинг и кэширование ответов
                resp_pos = 12
                _, resp_pos = parse_dns_name(response, resp_pos)
                resp_pos += 4  # Пропускаем QTYPE + QCLASS

                ancount = struct.unpack('!H', response[6:8])[0]

                for _ in range(ancount):
                    name, resp_pos = parse_dns_name(response, resp_pos)
                    rtype = struct.unpack('!H', response[resp_pos:resp_pos + 2])[0]
                    rclass = struct.unpack('!H', response[resp_pos + 2:resp_pos + 4])[0]
                    ttl = struct.unpack('!I', response[resp_pos + 4:resp_pos + 8])[0]
                    rdlength = struct.unpack('!H', response[resp_pos + 8:resp_pos + 10])[0]
                    resp_pos += 10

                    rdata = parse_rdata(response, resp_pos, rtype, rdlength)
                    resp_pos += rdlength

                    # Кэширование (если запись соответствует запросу)
                    if name == qname and rtype == qtype:
                        cache[(name, rtype, rclass)] = (rdata, time.time() + ttl)

                sock.sendto(response, addr)

            except socket.timeout:
                # SERVFAIL - форвардер не ответил: 0x8182 = ответ + RCODE=2
                tid = data[:2]
                header = tid + b'\x81\x82' + b'\x00\x01' + b'\x00\x00\x00\x00\x00\x00'
                question_pos = 12
                _, question_pos = parse_dns_name(data, question_pos)
                question = data[12:question_pos + 4]
                sock.sendto(header + question, addr)
            finally:
                fwd.close()

        except Exception as e:
            print(f"Error: {e}")
            continue


if __name__ == '__main__':
    main()
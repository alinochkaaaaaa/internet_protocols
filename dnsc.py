import socket
import struct
import sys
import time


# (домен, тип): (IP_байты, время_истечения)
cache = {}


def main():
    port = 5354  # не 53, чтобы не конфликтовать
    forwarder = ('8.8.8.8', 53)  # Google DNS по умолчанию

    # парсинг
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

    # создаем сокет: AF_INET - IPv4, SOCK_DGRAM - UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', port))
    print(f"DNS Server on port {port}, forwarder {forwarder[0]}:{forwarder[1]}")

    # обрабатываем запрос
    while True:
        data, addr = sock.recvfrom(512)

        # Parse DNS name
        pos = 12  # after header 12 bytes
        labels = []

        while pos < len(data):
            length = data[pos]
            if length == 0:  # 0 = конец имени
                pos += 1
                break
            pos += 1
            label = data[pos:pos + length].decode('ascii')
            labels.append(label)
            pos += length

        domain = '.'.join(labels)

        # чтение типа запрса
        if pos + 2 > len(data):  # недостаточно данных
            continue

        # '!H' - big-endian, unsigned short
        qtype = struct.unpack('!H', data[pos:pos + 2])[0]
        qtype_name = "A" if qtype == 1 else str(qtype)

        # проверка кэша, по ключу
        cache_key = (domain, qtype)
        if cache_key in cache:
            ip_bytes, expiry = cache[cache_key]
            if time.time() < expiry:
                # ttl уменьшается с каждым запросом
                ttl = int(expiry - time.time())
                # Заголовок ответа (12 байт)
                tid = data[:2]
                # QR=1 (ответ), Opcode=0, AA=0, TC=0, RD=0, RA=0, RCODE=0
                header = tid + b'\x81\x80' + b'\x00\x01' + b'\x00\x01' + b'\x00\x00\x00\x00'
                question = data[12:pos + 4]  # соекция вопроса из запроса
                # TYPE = 1 (A record), CLASS = 1 (IN), TTL (4 байта), RDATA length = 4 (IPv4), IP адрес (4 байта)
                answer = b'\xc0\x0c\x00\x01\x00\x01' + struct.pack('!I', ttl) + b'\x00\x04' + ip_bytes
                response = header + question + answer
                sock.sendto(response, addr)
                print(f"{addr[0]}, {qtype_name}, {domain}, cache")
                continue

        # пересылка запроса форвардеру
        print(f"{addr[0]}, {qtype_name}, {domain}, forwarder")

        fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        fwd.settimeout(5)  # Таймаут 5 секунд (для отказоустойчивости)
        try:
            fwd.sendto(data, forwarder)  # пересылаем исходный запрос
            response, _ = fwd.recvfrom(512)  # ждем ответ

            # Cache the response
            for i in range(len(response) - 6):
                # \xc0\x0c - указатель на имя, \x00\x01 - тип A
                if response[i:i + 2] == b'\xc0\x0c' and response[i + 2:i + 4] == b'\x00\x01':
                    if i + 8 <= len(response):
                        ttl = struct.unpack('!I', response[i + 4:i + 8])[0]
                        ip_start = i + 12
                        if ip_start + 4 <= len(response):
                            ip_bytes = response[ip_start:ip_start + 4]
                            # сохраняем в кэш с временем истечения
                            cache[cache_key] = (ip_bytes, time.time() + ttl)
                            break

            sock.sendto(response, addr)

        # обработка отказа форвардера
        except socket.timeout:
            # SERVFAIL, (RCODE = 2)
            tid = data[:2]
            header = tid + b'\x81\x82' + b'\x00\x01' + b'\x00\x00\x00\x00\x00\x00'
            question = data[12:pos + 4]
            sock.sendto(header + question, addr)
        finally:
            fwd.close()


if __name__ == '__main__':
    main()
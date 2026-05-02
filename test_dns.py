import socket

# DNS запрос для urfu.ru (A запись)
query = bytes([
    0x12, 0x34,  # ID
    0x01, 0x00,  # Flags (RD=1)
    0x00, 0x01,  # QDCOUNT = 1 вопрос
    0x00, 0x00,  # ANCOUNT
    0x00, 0x00,  # NSCOUNT
    0x00, 0x00,  # ARCOUNT
    0x04, 0x75, 0x72, 0x66, 0x75,  # "urfu"
    0x02, 0x72, 0x75,  # "ru"
    0x00,  # terminator
    0x00, 0x01,  # QTYPE = A
    0x00, 0x01   # QCLASS = IN
])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)

sock.sendto(query, ('127.0.0.1', 53))

try:
    response, addr = sock.recvfrom(512)
    print(f"Получен ответ от {addr}, {len(response)} байт")

    flags = (response[2] << 8) | response[3]
    rcode = flags & 0x000F

    if rcode == 0:
        print("OK - NOERROR")
        for i in range(len(response) - 4):
            if response[i:i + 2] == b'\xc0\x0c':
                ip_start = i + 12
                if ip_start + 4 <= len(response):
                    ip = '.'.join(str(b) for b in response[ip_start:ip_start + 4])
                    print(f"IP адрес: {ip}")
                    break
    elif rcode == 2:
        print("SERVFAIL - форвардер не ответил")
    else:
        print(f"Ошибка: RCODE={rcode}")

except socket.timeout:
    print("Таймаут - сервер не ответил")
finally:
    sock.close()
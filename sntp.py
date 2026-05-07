#SNTP сервер с возможностью "обмана" времени для Windows

import argparse # оброботка аргументов cmd
import logging
import socket # udp
import struct # binary data - sntp package
import time
from concurrent.futures import ThreadPoolExecutor # threads
from datetime import datetime

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# Константы SNTP
NTP_PORT = 123
ALTERNATIVE_PORT = 12345
NTP_EPOCH = 2208988800 # разница в секундах между 1900 и 1970 годом
NTP_PACKET_SIZE = 48
NTP_VERSION = 4
MODE_SERVER = 4
MODE_CLIENT = 3
LI_NO_WARNING = 0
STRATUM_PRIMARY = 1 # Уровень сервера
POLL_INTERVAL = 4
PRECISION = -6
ROOT_DELAY = 0
ROOT_DISPERSION = 0


class SNTPServer:
    def __init__(self, host='0.0.0.0', port=ALTERNATIVE_PORT, delay=0, max_workers=10):
        self.host = host # Слушаем все интерфейсы
        self.port = port # Порт (по умолчанию 12345)
        self.delay = delay # Смещение времени
        self.running = False
        self.socket = None
        self.executor = ThreadPoolExecutor(max_workers=max_workers) # Пул потоков

    def start(self):
        """Запуск сервера"""
        try:
            # Создаем UDP сокет
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # для Windows: переиспользование адреса
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

            # Пробуем привязаться к порту
            try:
                self.socket.bind((self.host, self.port))
            except PermissionError:
                logger.error(f"Нет прав для порта {self.port}. На Windows порты ниже 1024 требуют прав администратора.")
                logger.info(f"Попробуйте порт {ALTERNATIVE_PORT} или запустите от имени администратора")
                return False
            except OSError as e:
                if e.winerror == 10048:  # Порт уже используется
                    logger.error(f"Порт {self.port} уже используется другой программой")
                else:
                    logger.error(f"Ошибка привязки к порту: {e}")
                return False

            self.running = True

            logger.info(f"SNTP сервер запущен на {self.host}:{self.port}")
            logger.info(f"Смещение времени: {self.delay} секунд")
            logger.info(f"Потоков в пуле: {self.executor._max_workers}")
            logger.info("Ожидание подключений...")

            # Получаем информацию о сетевых интерфейсах
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            logger.info(f"Имя компьютера: {hostname}")
            logger.info(f"Локальный IP: {local_ip}")
            logger.info("Сервер готов к работе. Нажмите Ctrl+C для остановки.")

            # Основной цикл обработки запросов
            while self.running:
                try:
                    # Устанавливаем таймаут для возможности проверки running
                    self.socket.settimeout(1.0)

                    # Получаем данные
                    data, addr = self.socket.recvfrom(1024)

                    # Отправляем в пул потоков
                    self.executor.submit(self.handle_client, data, addr)

                except socket.timeout:
                    # Таймаут - продолжаем цикл
                    continue
                except Exception as e:
                    logger.error(f"Ошибка при получении данных: {e}")

        except Exception as e:
            logger.error(f"Критическая ошибка: {e}")
            return False

    def stop(self):
        """Остановка сервера"""
        logger.info("Останавливаем сервер...")
        self.running = False
        if self.socket:
            self.socket.close()
        self.executor.shutdown(wait=True)
        logger.info("Сервер остановлен")

    def handle_client(self, data, addr):
        """Обработка клиентского запроса"""
        client_ip, client_port = addr
        logger.info(f"Получен запрос от {client_ip}:{client_port}")

        try:
            # Проверяем минимальный размер пакета
            if len(data) < NTP_PACKET_SIZE:
                logger.warning(f"Слишком короткий пакет ({len(data)} байт) от {client_ip}")
                return

            # Анализируем первые байты
            if len(data) >= 1:
                first_byte = data[0]
                li = (first_byte >> 6) & 0x03 # (Leap Indicator) - 2 бита
                vn = (first_byte >> 3) & 0x07 # (Version Number) - 3 бита
                mode = first_byte & 0x07 # Mode - 3 бита
                logger.info(f"Запрос: LI={li}, VN={vn}, Mode={mode}")

            # Создаем ответ
            response = self.create_response(data)

            # Отправляем ответ
            self.socket.sendto(response, addr)
            logger.info(f"Ответ отправлен клиенту {client_ip}:{client_port}")
            logger.info(f"Размер ответа: {len(response)} байт")

        except Exception as e:
            logger.error(f"Ошибка обработки запроса от {client_ip}: {e}")
            import traceback
            traceback.print_exc()

    def create_response(self, request_data):
        """Создание SNTP ответа"""
        # Получаем текущее время с учетом смещения
        current_time = time.time() + self.delay

        # Конвертируем в NTP время
        ntp_time = current_time + NTP_EPOCH

        # Формируем первый байт: LI (2 бита) + VN (3 бита) + Mode (3 бита)
        first_byte = (LI_NO_WARNING << 6) | (NTP_VERSION << 3) | MODE_SERVER

        # Создаем буфер для ответа (48 байт)
        response = bytearray(48)

        # Заполняем заголовок (первые 12 байт)
        response[0] = first_byte  # LI, VN, Mode
        response[1] = STRATUM_PRIMARY  # Stratum (первичный сервер)
        response[2] = POLL_INTERVAL  # Poll
        response[3] = PRECISION & 0xFF  # Precision (как signed char)

        # Root Delay (4 байта) - в формате NTP с фиксированной точкой
        response[4:8] = struct.pack('!I', 0)

        # Root Dispersion (4 байта)
        response[8:12] = struct.pack('!I', 0)

        # Reference ID (4 байта) - для stratum 1 это может быть идентификатор источника
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            # Конвертируем IP в 4 байта
            ip_bytes = socket.inet_aton(local_ip)
            response[12:16] = ip_bytes
        except:
            response[12:16] = struct.pack('!I', 0)

        # Reference Timestamp (8 байт) - время последней синхронизации
        # Используем текущее время
        ref_seconds = int(ntp_time)
        ref_fraction = int((ntp_time - ref_seconds) * 2 ** 32)
        response[16:20] = struct.pack('!I', ref_seconds)
        response[20:24] = struct.pack('!I', ref_fraction)

        # Originate Timestamp (8 байт) - время отправки запроса клиентом
        # Извлекаем из запроса или используем 0
        if len(request_data) >= 48:
            response[24:32] = request_data[40:48]  # Копируем transmit timestamp из запроса
        else:
            response[24:32] = struct.pack('!Q', 0)

        # Receive Timestamp (8 байт) - время получения запроса
        recv_seconds = int(ntp_time)
        recv_fraction = int((ntp_time - recv_seconds) * 2 ** 32)
        response[32:36] = struct.pack('!I', recv_seconds)
        response[36:40] = struct.pack('!I', recv_fraction)

        # Transmit Timestamp (8 байт) - время отправки ответа
        response[40:44] = struct.pack('!I', recv_seconds)
        response[44:48] = struct.pack('!I', recv_fraction)

        return bytes(response)

    def _extract_transmit_timestamp(self, data):
        """Извлечение временной метки отправки"""
        if len(data) >= 48:
            return data[40:48]
        # Если нет метки, возвращаем нули
        return struct.pack('!Q', 0)  # 8 байт нулей


def test_ntp_client(server_ip='127.0.0.1', port=ALTERNATIVE_PORT):
    """Тестовая функция для отправки NTP запроса"""
    try:
        # Создаем UDP сокет
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(5)

        request = bytearray(48)
        request[0] = (0 << 6) | (4 << 3) | 3

        # Добавляем transmit timestamp (текущее время)
        current_time = time.time() + NTP_EPOCH
        seconds = int(current_time)
        fraction = int((current_time - seconds) * 2 ** 32)
        request[40:44] = struct.pack('!I', seconds)
        request[44:48] = struct.pack('!I', fraction)

        # Отправляем запрос
        logger.info(f"Отправка тестового запроса к {server_ip}:{port}")
        start_time = time.time()
        client.sendto(request, (server_ip, port))

        # Получаем ответ
        data, addr = client.recvfrom(1024)
        end_time = time.time()

        if len(data) >= 48:
            logger.info(f"Получен ответ от {addr}")
            logger.info(f"Время ответа: {(end_time - start_time) * 1000:.2f} мс")
            logger.info(f"Размер ответа: {len(data)} байт")

            # Парсим ответ
            li_vn_mode = data[0]
            stratum = data[1]
            poll = data[2]
            precision = data[3]

            logger.info(f"LI/VN/Mode: {li_vn_mode:08b} (dec: {li_vn_mode})")
            logger.info(f"Stratum: {stratum}")
            logger.info(f"Poll: {poll}")
            logger.info(f"Precision: {precision}")

            # Извлекаем transmit timestamp (время сервера)
            transmit_seconds = struct.unpack('!I', data[40:44])[0]
            transmit_fraction = struct.unpack('!I', data[44:48])[0]
            ntp_time = transmit_seconds + transmit_fraction / 2 ** 32 - NTP_EPOCH

            # Текущее время без смещения
            current_time = time.time()

            logger.info(f"Время сервера (NTP): {datetime.fromtimestamp(ntp_time)}")
            logger.info(f"Локальное время: {datetime.fromtimestamp(current_time)}")
            logger.info(f"Разница: {ntp_time - current_time:.2f} сек")

            # Проверяем смещение
            expected_offset = ntp_time - current_time
            logger.info(f"Фактическое смещение: {expected_offset:.2f} сек")

    except socket.timeout:
        logger.error("Таймаут - сервер не отвечает")
    except Exception as e:
        logger.error(f"Ошибка теста: {e}")
        import traceback
        traceback.print_exc()
    finally:
        client.close()


def main():
    parser = argparse.ArgumentParser(description='SNTP сервер для Windows')
    parser.add_argument('-d', '--delay', type=int, default=0,
                        help='Смещение времени в секундах (по умолчанию 0)')
    parser.add_argument('-p', '--port', type=int, default=ALTERNATIVE_PORT,
                        help=f'Порт для прослушивания (по умолчанию {ALTERNATIVE_PORT})')
    parser.add_argument('--test', action='store_true',
                        help='Запустить тестового клиента')
    parser.add_argument('--test-ip', default='127.0.0.1',
                        help='IP для тестирования')

    args = parser.parse_args()

    # Режим тестирования
    if args.test:
        test_ntp_client(args.test_ip, args.port)
        return

    # Запуск сервера
    server = SNTPServer(port=args.port, delay=args.delay)

    try:
        # Запускаем сервер (он работает в основном потоке)
        server.start()
    except KeyboardInterrupt:
        logger.info("Получен сигнал завершения")
    finally:
        server.stop()


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import imaplib
import email
from email.header import decode_header
import getpass # Скрытый ввод пароля
import argparse
import sys
import ssl # STARTTLS
import re
from email.utils import parsedate_to_datetime # Преобразование даты из письма


def decode_mime_header(value):
    """Декодирует заголовок MIME."""
    if value is None:
        return ""
    decoded_parts = []
    for part, encoding in decode_header(value):
        if isinstance(part, bytes):
            try:
                if encoding:
                    part = part.decode(encoding, errors='replace')
                else:
                    for enc in ['utf-8', 'cp1251', 'koi8-r', 'iso-8859-5']:
                        try:
                            part = part.decode(enc)
                            break
                        except:
                            continue
                    else:
                        part = part.decode('utf-8', errors='replace')
            except:
                part = str(part)
        decoded_parts.append(str(part))
    return ''.join(decoded_parts)


def get_attachments_info(msg):
    """Возвращает список вложений с именами и размерами."""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = part.get_content_type()

            if "attachment" in content_disposition.lower() or \
                    (content_type not in ["text/plain", "text/html", "multipart/alternative", "multipart/related"] and
                     part.get_filename()):

                filename = part.get_filename()
                if filename:
                    filename = decode_mime_header(filename)
                    if '/' in filename:
                        filename = filename.split('/')[-1]
                    elif '\\' in filename:
                        filename = filename.split('\\')[-1]
                else:
                    filename = f"(без имени) {content_type}"

                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0

                attachments.append({
                    "filename": filename,
                    "size": size,
                    "type": content_type
                })

    return attachments


def parse_args():
    parser = argparse.ArgumentParser(
        description="IMAP клиент для просмотра писем",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # python3 imap.py --ssl ...
    parser.add_argument("--ssl", action="store_true",
                        help="использовать SSL (IMAPS, порт 993)")
    # -s imap.mail.ru:143
    parser.add_argument("-s", "-server", dest="server", required=True,
                        help="адрес[:порт] IMAP-сервера")
    # -n 1 10; -n 5
    parser.add_argument("-n", nargs='+', dest="range",
                        help="диапазон писем: N1 или N1 N2")
    # -u user@mail.ru
    parser.add_argument("-u", "-user", dest="user", required=True,
                        help="имя пользователя (email или логин)")
    return parser.parse_args()


def parse_server_address(addr):
    """Разбирает адрес[:порт]"""
    if ':' in addr:
        host, port = addr.rsplit(':', 1)
        return host, int(port)
    else:
        return addr, None


def parse_imap_response(response, key):
    """Парсит ответ IMAP для получения числового значения."""
    try:
        # Ответ в формате: b'* STATUS "INBOX" (MESSAGES 6)'
        decoded = response[0].decode()
        # Ищем цифры после ключа
        match = re.search(f'{key}\\s+(\\d+)', decoded)
        if match:
            return int(match.group(1))
        # Альтернативный парсинг
        parts = decoded.split()
        for i, part in enumerate(parts):
            if part == key and i + 1 < len(parts):
                return int(parts[i + 1].strip(')'))
    except:
        pass
    return 0


def connect_and_login(host, port, user, password, use_ssl):
    """Подключается и логинится с автоматическим определением STARTTLS."""

    try:
        print(f"Подключение к {host}:{port} {'с SSL' if use_ssl else 'без шифрования'}")

        if use_ssl:
            # сразу зашифрованное
            imap = imaplib.IMAP4_SSL(host, port)
        else:
            # обычное, без шифрования
            imap = imaplib.IMAP4(host, port)

        print(f"Аутентификация...")
        imap.login(user, password)
        print("Аутентификация успешна")
        return imap, False

    except imaplib.IMAP4.error as e:
        error_msg = str(e).lower()

        # сервер требует STARTTLS
        if "starttls" in error_msg or "privacyrequired" in error_msg:
            print("Сервер требует STARTTLS")

            try:
                imap = imaplib.IMAP4(host, port)
                print("Активация STARTTLS...")
                imap.starttls(ssl.create_default_context()) # ШИФРОВАНИЕ
                print("STARTTLS активирован")

                print(f"Аутентификация пользователя {user}...")
                imap.login(user, password)
                print("Аутентификация успешна")
                return imap, True

            except imaplib.IMAP4.error as e2:
                print(f"Ошибка аутентификации после STARTTLS: {e2}", file=sys.stderr)

                if "mail.ru" in host.lower():
                    print("\nДля Mail.ru требуется пароль приложения")
                    print("   https://account.mail.ru/security/app-passwords")
                elif "gmail.com" in host.lower():
                    print("\nДля Gmail требуется пароль приложения")
                    print("   https://myaccount.google.com/apppasswords")

                sys.exit(1)
        else:
            print(f"Ошибка аутентификации: {e}", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        print(f"Ошибка подключения: {e}", file=sys.stderr)
        sys.exit(1)


def main():
    args = parse_args()

    server_host, server_port = parse_server_address(args.server)

    if server_port is None:
        if args.ssl:
            server_port = 993
        else:
            server_port = 143

    print(f"\nПодключение к {server_host}:{server_port}")
    password = getpass.getpass(f"Пароль для {args.user}: ")

    imap, used_starttls = connect_and_login(server_host, server_port, args.user, password, args.ssl)

    # Выбираем папку INBOX
    try:
        status, mailbox_data = imap.select("INBOX", readonly=True)
        if status != 'OK':
            print("Ошибка: не удалось открыть папку INBOX", file=sys.stderr)
            sys.exit(1)
        print("Папка INBOX открыта")
    except Exception as e:
        print(f"Ошибка при открытии INBOX: {e}", file=sys.stderr)
        sys.exit(1)

    # Получаем количество писем
    status, response = imap.status("INBOX", "(MESSAGES)")
    if status != 'OK':
        print("Ошибка получения количества писем", file=sys.stderr)
        sys.exit(1)

    total = parse_imap_response(response, "MESSAGES")

    if total == 0:
        print("\nВ почтовом ящике нет писем.")
        imap.close()
        imap.logout()
        return

    # Определяем диапазон
    if args.range:
        if len(args.range) == 1:
            start = end = int(args.range[0])
        elif len(args.range) == 2:
            start, end = int(args.range[0]), int(args.range[1])
        else:
            print("Ошибка: неверный формат диапазона", file=sys.stderr)
            sys.exit(1)

        if start < 1 or end > total or start > end:
            print(f"Ошибка: диапазон должен быть от 1 до {total}", file=sys.stderr)
            sys.exit(1)
    else:
        start, end = 1, total

    print(f"\nСтатистика:")
    print(f"Пользователь: {args.user}")
    print(f"Сервер: {server_host}:{server_port}", end="")
    if args.ssl:
        print(" (SSL/TLS)")
    elif used_starttls:
        print(" (STARTTLS)")
    else:
        print(" (без шифрования)")
    print(f"Всего писем: {total}")

    success_count = 0
    for num in range(start, end + 1):
        try:
            print(f"\nПисьмо #{num} ({success_count + 1}/{end - start + 1})")

            # Получаем заголовки
            status, data = imap.fetch(str(num), "(RFC822.HEADER)")
            if status != 'OK' or not data[0]:
                print(f"Не удалось получить заголовки")
                continue

            msg = email.message_from_bytes(data[0][1])

            from_ = decode_mime_header(msg.get("From", "(не указан)"))
            to_ = decode_mime_header(msg.get("To", "(не указан)"))
            subject = decode_mime_header(msg.get("Subject", "(без темы)"))
            date_raw = msg.get("Date", "")

            try:
                dt = parsedate_to_datetime(date_raw)
                date = dt.strftime("%d.%m.%Y %H:%M:%S")
            except:
                date = date_raw if date_raw else "дата неизвестна"

            # Получаем размер письма
            status, size_data = imap.fetch(str(num), "(RFC822.SIZE)")
            if status == 'OK' and size_data[0]:
                # Парсим ответ: b'985 (RFC822.SIZE 12345)'
                size_match = re.search(r'RFC822\.SIZE\s+(\d+)', str(size_data[0]))
                if size_match:
                    size = int(size_match.group(1))
                    if size < 1024:
                        size_str = f"{size} байт"
                    elif size < 1024 * 1024:
                        size_str = f"{size / 1024:.1f} КБ"
                    else:
                        size_str = f"{size / (1024 * 1024):.2f} МБ"
                else:
                    size_str = "неизвестно"
            else:
                size_str = "неизвестно"

            print(f"От:      {from_}")
            print(f"Кому:    {to_}")
            print(f"Тема:    {subject}")
            print(f"Дата:    {date}")
            print(f"Размер:  {size_str}")

            # Получаем вложения
            try:
                status, full_data = imap.fetch(str(num), "(RFC822)")
                if status == 'OK' and full_data[0]:
                    full_msg = email.message_from_bytes(full_data[0][1])
                    attachments = get_attachments_info(full_msg)

                    if attachments:
                        total_size = sum(att['size'] for att in attachments)
                        if total_size < 1024:
                            size_total = f"{total_size} байт"
                        elif total_size < 1024 * 1024:
                            size_total = f"{total_size / 1024:.1f} КБ"
                        else:
                            size_total = f"{total_size / (1024 * 1024):.2f} МБ"

                        print(f"Вложений: {len(attachments)} (всего {size_total})")
                        for i, att in enumerate(attachments, 1):
                            if att['size'] < 1024:
                                att_size = f"{att['size']} байт"
                            elif att['size'] < 1024 * 1024:
                                att_size = f"{att['size'] / 1024:.1f} КБ"
                            else:
                                att_size = f"{att['size'] / (1024 * 1024):.2f} МБ"
                            print(f"     {i}. {att['filename']} ({att_size})")
                    else:
                        print(f"Вложений: нет")
                else:
                    print(f"Вложений: не удалось получить")
            except Exception as e:
                print(f"Вложений: ошибка при получении ({str(e)[:50]})")

            success_count += 1

        except Exception as e:
            print(f"Ошибка обработки письма {num}: {e}")

    print(f"Готово! Обработано писем: {success_count}")

    try:
        imap.close()
        imap.logout()
    except:
        pass


if __name__ == "__main__":
    main()
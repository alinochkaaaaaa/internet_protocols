import imaplib
import email
from email.header import decode_header
import getpass
import argparse
import sys
import ssl
import re
from email.utils import parsedate_to_datetime


def decode_mime_header(value):
    """Декодирует заголовок MIME в читаемую строку."""
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
    """Возвращает список вложений с именами, размерами и типами."""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            content_type = part.get_content_type()

            is_attachment = False
            if "attachment" in content_disposition.lower():
                is_attachment = True
            elif part.get_filename() and content_type not in ["text/plain", "text/html", "multipart/alternative",
                                                              "multipart/related"]:
                is_attachment = True

            if is_attachment:
                filename = part.get_filename()
                if filename:
                    filename = decode_mime_header(filename)
                    if '/' in filename:
                        filename = filename.split('/')[-1]
                    elif '\\' in filename:
                        filename = filename.split('\\')[-1]
                else:
                    ext_map = {
                        'image/jpeg': 'jpg', 'image/png': 'png', 'image/gif': 'gif',
                        'image/webp': 'webp', 'video/mp4': 'mp4', 'video/webm': 'webm',
                        'application/pdf': 'pdf', 'application/zip': 'zip', 'text/plain': 'txt',
                    }
                    ext = ext_map.get(content_type, 'bin')
                    filename = f"attachment.{ext}"

                payload = part.get_payload(decode=True)
                size = len(payload) if payload else 0

                if content_type.startswith('image/'):
                    category = 'Изображение'
                elif content_type.startswith('video/'):
                    category = 'Видео'
                elif content_type.startswith('audio/'):
                    category = 'Аудио'
                elif content_type == 'application/pdf':
                    category = 'PDF'
                elif content_type == 'application/zip' or content_type.endswith('zip'):
                    category = 'Архив'
                elif content_type == 'text/plain':
                    category = 'Текст'
                else:
                    category = 'Неизвестное содержимое'

                attachments.append({
                    "filename": filename,
                    "size": size,
                    "type": content_type,
                    "category": category
                })

    return attachments


def decode_email_body(msg):
    """Извлекает только русские предложения, отсекая HTML/CSS."""
    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            if "attachment" in content_disposition.lower():
                continue

            payload = part.get_payload(decode=True)
            if not payload:
                continue

            text = ""
            if content_type == "text/plain":
                try:
                    text = payload.decode('utf-8', errors='replace')
                except:
                    text = payload.decode('cp1251', errors='replace')
            elif content_type == "text/html":
                try:
                    html_content = payload.decode('utf-8', errors='replace')
                except:
                    html_content = payload.decode('cp1251', errors='replace')

                # очистка HTML
                html_content = re.sub(r'<style[^>]*>.*?</style>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                html_content = re.sub(r'<script[^>]*>.*?</script>', '', html_content, flags=re.DOTALL | re.IGNORECASE)
                html_content = re.sub(r'<[^>]+>', ' ', html_content)
                html_content = re.sub(r'&nbsp;', ' ', html_content)
                html_content = re.sub(r'&amp;', ' ', html_content)
                html_content = re.sub(r'&lt;', ' ', html_content)
                html_content = re.sub(r'&gt;', ' ', html_content)
                html_content = re.sub(r'&quot;', ' ', html_content)
                html_content = re.sub(r'&#\d+;', ' ', html_content)
                html_content = re.sub(r'&[a-z]+;', ' ', html_content)
                html_content = re.sub(r'[͏⠀]', ' ', html_content)

                text = html_content

            if text:
                body_parts.append(text)
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            content_type = msg.get_content_type()
            if content_type == "text/html":
                try:
                    html_content = payload.decode('utf-8', errors='replace')
                except:
                    html_content = payload.decode('cp1251', errors='replace')
                html_content = re.sub(r'<[^>]+>', ' ', html_content)
                html_content = re.sub(r'&nbsp;', ' ', html_content)
                html_content = re.sub(r'&[a-z]+;', ' ', html_content)
                text = html_content
            else:
                try:
                    text = payload.decode('utf-8', errors='replace')
                except:
                    text = payload.decode('cp1251', errors='replace')
            body_parts.append(text)

    raw_text = ' '.join(body_parts)
    raw_text = re.sub(r'\s+', ' ', raw_text)

    # Ищем все русские предложения
    russian_sentences = re.findall(r'[А-ЯЁ][^.!?]*[.!?]', raw_text)
    russian_sentences += re.findall(r'[а-яё][^.!?]*[.!?]', raw_text)

    # Очищаем каждое предложение
    clean_sentences = []
    for sent in russian_sentences:
        sent = sent.strip()
        if len(sent) < 10:
            continue
        if not re.search(r'[а-яА-ЯёЁ]', sent):
            continue
        if re.search(r'[{}=;]', sent):
            continue
        sent = re.sub(r'^&?\s*', '', sent)
        if sent:
            clean_sentences.append(sent)

    # Убираем дубликаты (сохраняем порядок)
    unique = []
    for s in clean_sentences:
        # Проверяем, не было ли уже такого предложения
        if s not in unique:
            # Также проверяем, не является ли s началом другого предложения
            is_duplicate = False
            for existing in unique:
                if s in existing or existing in s:
                    # Если одно предложение содержит другое, оставляем более длинное
                    if len(s) > len(existing):
                        unique.remove(existing)
                        unique.append(s)
                    is_duplicate = True
                    break
            if not is_duplicate:
                unique.append(s)

    result = ' '.join(unique)

    if not result:
        attachments = get_attachments_info(msg)
        if attachments:
            img_cnt = sum(1 for a in attachments if a['type'].startswith('image/'))
            if img_cnt:
                return f"(письмо содержит {img_cnt} изображение(й), текста нет)"
            return f"(письмо содержит {len(attachments)} вложение(й), текста нет)"
        return "(письмо не содержит читаемого текста)"

    if len(result) > 2000:
        result = result[:2000] + "... (содержимое обрезано)"

    return result


def parse_args():
    parser = argparse.ArgumentParser(description="IMAP клиент для просмотра писем")
    parser.add_argument("--ssl", action="store_true", help="использовать SSL")
    parser.add_argument("-s", "-server", dest="server", required=True, help="адрес[:порт] IMAP-сервера")
    parser.add_argument("-n", nargs='+', dest="range", help="диапазон писем: N1 или N1 N2")
    parser.add_argument("-u", "-user", dest="user", required=True, help="имя пользователя")
    return parser.parse_args()


def parse_server_address(addr):
    if ':' in addr:
        host, port = addr.rsplit(':', 1)
        return host, int(port)
    return addr, None


def parse_imap_response(response, key):
    try:
        decoded = response[0].decode()
        match = re.search(f'{key}\\s+(\\d+)', decoded)
        if match:
            return int(match.group(1))
    except:
        pass
    return 0


def connect_and_login(host, port, user, password, use_ssl):
    try:
        print(f"[*] Подключение к {host}:{port} {'с SSL' if use_ssl else 'без шифрования'}")
        if use_ssl:
            imap = imaplib.IMAP4_SSL(host, port)
        else:
            imap = imaplib.IMAP4(host, port)

        print(f"Аутентификация...")
        imap.login(user, password)
        print("утентификация успешна")
        return imap, False
    except imaplib.IMAP4.error as e:
        error_msg = str(e).lower()
        if "starttls" in error_msg or "privacyrequired" in error_msg:
            print("Сервер требует STARTTLS")
            imap = imaplib.IMAP4(host, port)
            print("Активация STARTTLS...")
            imap.starttls(ssl.create_default_context())
            print("STARTTLS активирован")
            imap.login(user, password)
            print("Аутентификация успешна")
            return imap, True
        else:
            print(f"Ошибка аутентификации: {e}", file=sys.stderr)
            sys.exit(1)
    except Exception as e:
        print(f"Ошибка подключения: {e}", file=sys.stderr)
        sys.exit(1)


def ask_user_yes_no(question):
    while True:
        answer = input(f"{question} (y/n): ").strip().lower()
        if answer in ['y', 'yes', '1', 'д', 'да']:
            return True
        elif answer in ['n', 'no', '0', 'н', 'нет']:
            return False
        else:
            print("  Please answer 'y' (yes) or 'n' (no)")


def display_message(imap, num, current, total):
    try:
        print(f"\nMessage #{num} ({current}/{total})")

        status, data = imap.fetch(str(num), "(RFC822.HEADER)")
        if status != 'OK' or not data[0]:
            print(f"Cannot get headers")
            return False

        msg = email.message_from_bytes(data[0][1])

        from_ = decode_mime_header(msg.get("From", "(unknown)"))
        to_ = decode_mime_header(msg.get("To", "(unknown)"))
        subject = decode_mime_header(msg.get("Subject", "(no subject)"))
        date_raw = msg.get("Date", "")

        try:
            dt = parsedate_to_datetime(date_raw)
            date = dt.strftime("%d.%m.%Y %H:%M:%S")
        except:
            date = date_raw if date_raw else "date unknown"

        status, size_data = imap.fetch(str(num), "(RFC822.SIZE)")
        size_str = "unknown"
        if status == 'OK' and size_data[0]:
            size_match = re.search(r'RFC822\.SIZE\s+(\d+)', str(size_data[0]))
            if size_match:
                size = int(size_match.group(1))
                if size < 1024:
                    size_str = f"{size} bytes"
                elif size < 1024 * 1024:
                    size_str = f"{size / 1024:.1f} KB"
                else:
                    size_str = f"{size / (1024 * 1024):.2f} MB"

        print(f"From:    {from_}")
        print(f"To:      {to_}")
        print(f"Subject: {subject}")
        print(f"Date:    {date}")
        print(f"Size:    {size_str}")

        status, full_data = imap.fetch(str(num), "(RFC822)")
        if status == 'OK' and full_data[0]:
            full_msg = email.message_from_bytes(full_data[0][1])
            attachments = get_attachments_info(full_msg)

            if attachments:
                total_size = sum(att['size'] for att in attachments)
                if total_size < 1024:
                    size_total = f"{total_size} bytes"
                elif total_size < 1024 * 1024:
                    size_total = f"{total_size / 1024:.1f} KB"
                else:
                    size_total = f"{total_size / (1024 * 1024):.2f} MB"

                print(f" Attachments: {len(attachments)} (total {size_total})")
                for i, att in enumerate(attachments, 1):
                    if att['size'] < 1024:
                        att_size = f"{att['size']} bytes"
                    elif att['size'] < 1024 * 1024:
                        att_size = f"{att['size'] / 1024:.1f} KB"
                    else:
                        att_size = f"{att['size'] / (1024 * 1024):.2f} MB"
                    print(f"     {i}. {att['category']}: {att['filename']} ({att_size})")
            else:
                print(f" Attachments: none")

            if ask_user_yes_no(f"\nRead message #{num} content?"):
                body = decode_email_body(full_msg)
                print("\n" + "─" * 40)
                print("Message content:")
                print("─" * 40)
                print(body)
                print("─" * 40)

        return True
    except Exception as e:
        print(f"Error processing message {num}: {e}")
        return False


def main():
    args = parse_args()

    server_host, server_port = parse_server_address(args.server)

    if server_port is None:
        server_port = 993 if args.ssl else 143

    print(f"\nonnecting to {server_host}:{server_port}")
    password = getpass.getpass(f"Password for {args.user}: ")

    imap, used_starttls = connect_and_login(server_host, server_port, args.user, password, args.ssl)

    try:
        status, _ = imap.select("INBOX", readonly=True)
        if status != 'OK':
            print("Error: cannot open INBOX", file=sys.stderr)
            sys.exit(1)
        print("[+] INBOX opened")
    except Exception as e:
        print(f"Error opening INBOX: {e}", file=sys.stderr)
        sys.exit(1)

    status, response = imap.search(None, "ALL")
    if status != 'OK':
        print("Error getting message list", file=sys.stderr)
        sys.exit(1)

    all_ids = [int(x) for x in response[0].split()]
    all_ids.sort(reverse=True)
    total = len(all_ids)

    if total == 0:
        print("\nNo messages in mailbox.")
        imap.close()
        imap.logout()
        return

    print(f"\nStatistics:")
    print(f"User: {args.user}")
    print(
        f"Server: {server_host}:{server_port} ({'SSL/TLS' if args.ssl else 'STARTTLS' if used_starttls else 'no encryption'})")
    print(f"Total messages: {total}")
    print(f"Pagination: showing 10 newest messages at a time")

    ids_to_show = []
    page_size = 10
    offset = 0

    while offset < len(all_ids):
        page_ids = all_ids[offset:offset + page_size]
        page_start = offset + 1
        page_end = min(offset + page_size, len(all_ids))

        if offset > 0:
            if not ask_user_yes_no(f"\nShow next {page_size} messages ({page_start}-{page_end})?"):
                break

        ids_to_show.extend(page_ids)

        for idx, num in enumerate(page_ids, 1):
            display_message(imap, num, offset + idx, len(all_ids))

        offset += page_size

    if not ids_to_show:
        print("\nNo messages to display.")

    print(f"Done! Processed {len(ids_to_show)} messages")

    imap.close()
    imap.logout()


if __name__ == "__main__":
    main()
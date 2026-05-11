import socket
import ssl
import base64 # code password
import getpass # hidden pass
import os # files, paths
import sys
import argparse
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.text import MIMEText
from email.utils import formatdate


def read_resp(sock, verbose=False):
    """Читает ответ от сервера, поддерживает многострочные ответы:
    читает строки, пока не встретит строку с пробелом после кода."""
    lines = []
    while True:
        try:
            line = sock.recv(1024).decode('utf-8', errors='replace')
        except Exception as e:
            if verbose:
                sys.stderr.write(f"[ERROR] Failed to read: {e}\n")
            return lines

        if not line:
            break

        clean_line = line.rstrip()
        if verbose and clean_line:
            # Не выводим MIME-заголовки
            if not clean_line.startswith('MIME') and not clean_line.startswith(
                    'Content-') and not clean_line.startswith('------'):
                sys.stderr.write(f"[RECV] {clean_line}\n")
        lines.append(line)

        # Если 4-й символ - пробел, значит это последняя строка ответа - "250 OK"
        if len(line) >= 4 and line[3] == ' ':
            break
    return lines


def send_cmd(sock, cmd, verbose=False):
    """Отправляет команду серверу."""
    if verbose:
        if cmd.startswith('AUTH') or 'AUTH' in cmd:
            sys.stderr.write(f"[SEND] {cmd}\n")
        elif cmd and not cmd.startswith('dXN') and not cmd.startswith('cGFz') and len(cmd) < 100:
            sys.stderr.write(f"[SEND] {cmd}\n")
        elif len(cmd) > 100 and not cmd.startswith('EHLO'):
            sys.stderr.write(f"[SEND] [MESSAGE DATA - {len(cmd)} bytes]\n")
        else:
            sys.stderr.write(f"[SEND] {cmd}\n")
    sock.send((cmd + "\r\n").encode())


def parse_response(lines):
    """Извлекает код ответа из последней строки многострочного ответа."""
    if not lines:
        return None
    last_line = lines[-1]
    if len(last_line) >= 3 and last_line[:3].isdigit():
        return int(last_line[:3])
    return None


def smtp_auth(sock, user, password, verbose=False):
    """AUTH LOGIN."""
    if verbose:
        sys.stderr.write("[PROGRESS] Sending authentication request...\n")

    send_cmd(sock, "AUTH LOGIN", verbose)
    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 334:
        raise Exception(f"AUTH LOGIN failed (expected 334): {resp}")

    if verbose:
        sys.stderr.write("[PROGRESS] Sending username...\n")

    send_cmd(sock, base64.b64encode(user.encode()).decode(), verbose)
    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 334:
        raise Exception(f"AUTH user failed (expected 334): {resp}")

    if verbose:
        sys.stderr.write("[PROGRESS] Sending password...\n")

    send_cmd(sock, base64.b64encode(password.encode()).decode(), verbose)
    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 235:
        raise Exception(f"AUTH password failed (expected 235): {resp}")

    if verbose:
        sys.stderr.write("[PROGRESS] Authentication successful\n")


def construct_mime_mail(from_addr, to_addr, subject, directory):
    """Собирает MIME-письмо с картинками из каталога."""
    if not os.path.exists(directory):
        print(f"ERROR: Directory '{directory}' does not exist!", file=sys.stderr)
        sys.exit(1)

    files = os.listdir(directory)
    image_ext = ('.jpg', '.jpeg', '.png', '.gif', '.bmp')
    image_files = [f for f in files if f.lower().endswith(image_ext)]

    if not image_files:
        print(f"WARNING: No image files found in '{directory}'", file=sys.stderr)
        print(f"Supported formats: {', '.join(image_ext)}", file=sys.stderr)
        sys.exit(1)

    print(f"[PROGRESS] Found {len(image_files)} image(s) in directory: {directory}", file=sys.stderr)
    for img in image_files:
        print(f"[PROGRESS]   - {img}", file=sys.stderr)

    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg['Date'] = formatdate()

    text = MIMEText(f"Pictures from {directory}\n\nAttached files: {', '.join(image_files)}", 'plain', 'utf-8')
    msg.attach(text)

    attached = False
    for fname in image_files:
        with open(os.path.join(directory, fname), 'rb') as img_file:
            img_data = img_file.read()
            img = MIMEImage(img_data, name=os.path.basename(fname))
            msg.attach(img)
            attached = True

    return msg.as_string(), attached


def create_ssl_socket(sock, server, verbose=False):
    """Создает SSL-сокет из обычного сокета."""
    context = ssl.create_default_context()
    if verbose:
        sys.stderr.write("[PROGRESS] Establishing SSL connection...\n")
    return context.wrap_socket(sock, server_hostname=server)


def sendmail(server, port, use_ssl, from_addr, to_addr, subject, directory, auth, verbose):
    """Основная функция отправки."""
    print("[PROGRESS] Preparing email message...", file=sys.stderr)

    mime_text, has_images = construct_mime_mail(from_addr, to_addr, subject, directory)

    message_size_kb = len(mime_text) / 1024
    print(f"[PROGRESS] Message size: {len(mime_text)} bytes ({message_size_kb:.2f} KB)", file=sys.stderr)

    print(f"[PROGRESS] Connecting to SMTP server {server}:{port}...", file=sys.stderr)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(30)

    if use_ssl:
        sock = create_ssl_socket(sock, server, verbose)

    sock.connect((server, port))
    print("[PROGRESS] Connected to server", file=sys.stderr)

    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 220:
        raise Exception(f"Unexpected greeting: {resp}")

    print("[PROGRESS] Sending EHLO command...", file=sys.stderr)
    send_cmd(sock, f"EHLO {socket.gethostname()}", verbose)
    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 250:
        raise Exception(f"EHLO failed: {resp}")

    ehlo_response = ''.join(resp)

    if not use_ssl and "STARTTLS" in ehlo_response:
        print("[PROGRESS] Initiating STARTTLS...", file=sys.stderr)
        send_cmd(sock, "STARTTLS", verbose)
        resp = read_resp(sock, verbose)
        code = parse_response(resp)
        if code != 220:
            raise Exception(f"STARTTLS failed: {resp}")

        sock = create_ssl_socket(sock, server, verbose)
        print("[PROGRESS] STARTTLS completed, connection is now encrypted", file=sys.stderr)

        send_cmd(sock, f"EHLO {socket.gethostname()}", verbose)
        resp = read_resp(sock, verbose)
        code = parse_response(resp)
        if code != 250:
            raise Exception(f"EHLO after STARTTLS failed: {resp}")

    if auth:
        print("[PROGRESS] Authentication required. Please enter password.", file=sys.stderr)
        password = getpass.getpass("SMTP password: ")
        smtp_auth(sock, from_addr, password, verbose)

    print("[PROGRESS] Sending MAIL FROM command...", file=sys.stderr)
    send_cmd(sock, f"MAIL FROM:<{from_addr}>", verbose)
    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 250:
        raise Exception(f"MAIL FROM failed: {resp}")

    print("[PROGRESS] Sending RCPT TO command...", file=sys.stderr)
    send_cmd(sock, f"RCPT TO:<{to_addr}>", verbose)
    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 250:
        raise Exception(f"RCPT TO failed: {resp}")

    print("[PROGRESS] Sending DATA command...", file=sys.stderr)
    send_cmd(sock, "DATA", verbose)
    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 354:
        raise Exception(f"DATA failed: {resp}")

    print("[PROGRESS] Sending email content (images and text)...", file=sys.stderr)
    sock.send((mime_text + "\r\n.\r\n").encode())
    print("[PROGRESS] Email content sent, waiting for server confirmation...", file=sys.stderr)

    resp = read_resp(sock, verbose)
    code = parse_response(resp)
    if code != 250:
        raise Exception(f"DATA end failed: {resp}")

    print("[PROGRESS] Email accepted by server", file=sys.stderr)

    send_cmd(sock, "QUIT", verbose)
    read_resp(sock, verbose)
    sock.close()

    print("[PROGRESS] Connection closed", file=sys.stderr)
    print("\n[SUCCESS] Email sent successfully!", file=sys.stderr)
    print(f"[SUMMARY] From: {from_addr}", file=sys.stderr)
    print(f"[SUMMARY] To: {to_addr}", file=sys.stderr)
    print(f"[SUMMARY] Subject: {subject}", file=sys.stderr)
    print(f"[SUMMARY] Images attached: from directory '{directory}'", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(
        description='SMTP client for sending images as MIME attachments',
        epilog='Examples:\n'
               '  python3 smtp.py -s smtp.gmail.com:587 -t user@gmail.com -f sender@gmail.com -d ./pictures --auth\n'
               '  python3 smtp.py -s smtp.yandex.com:465 --ssl -t user@mail.ru -f sender@yandex.ru -d ./images --auth -v'
    )
    parser.add_argument('--ssl', action='store_true', help='use SSL from start (port 465)')
    parser.add_argument('-s', '--server', required=True,
                        help='SMTP server address[:port] (example: smtp.gmail.com:587)')
    parser.add_argument('-t', '--to', required=True, help='recipient email address')
    parser.add_argument('-f', '--from', dest='from_addr', required=True, help='sender email address')
    parser.add_argument('--subject', default='Happy Pictures', help='email subject (default: "Happy Pictures")')
    parser.add_argument('--auth', action='store_true', help='request SMTP authentication (password will be asked)')
    parser.add_argument('-v', '--verbose', action='store_true', help='show SMTP protocol details')
    parser.add_argument('-d', '--directory', default='.', help='directory with images (default: current directory)')
    args = parser.parse_args()

    if ':' in args.server:
        server, port_str = args.server.rsplit(':', 1)
        port = int(port_str)
    else:
        server = args.server
        port = 25
        print(f"[INFO] Port not specified, using default port {port}", file=sys.stderr)

    print("\n" + "=" * 60, file=sys.stderr)
    print("SMTP MIME Email Sender", file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)

    try:
        sendmail(
            server=server, port=port, use_ssl=args.ssl,
            from_addr=args.from_addr, to_addr=args.to, subject=args.subject,
            directory=args.directory, auth=args.auth, verbose=args.verbose
        )
    except Exception as e:
        print(f"\n[ERROR] {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
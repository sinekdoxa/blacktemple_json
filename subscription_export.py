"""Export a BLACKTEMPLE subscription as Xray profiles and an offline key picker."""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent
MAX_BODY = 4 * 1024 * 1024
# This application-wide protocol key is shipped with the exporter, not a user's identity.
# Use the literal UTF-8 string, NOT Base64-decoded bytes.
BUILTIN_SIGNING_KEY = 'Vy8Dpmn3wdMTaemIZiLDN8Knzw2cJaoNkcceOLooB3sPGtGkInMO8vBE1G/4AWKAq1t4BFFRY289aduMNxZr4A=='


def default_identity_path() -> Path:
    if sys.platform == 'win32':
        base = Path(os.environ.get('LOCALAPPDATA') or Path.home() / 'AppData/Local')
    elif sys.platform == 'darwin':
        base = Path.home() / 'Library/Application Support'
    else:
        base = Path(os.environ.get('XDG_CONFIG_HOME') or Path.home() / '.config')
    return base / 'blacktemple-subscription-export/identity.json'


class ExportError(Exception):
    """A diagnostic that is safe to show without exposing subscription secrets."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_identity(path: Path) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        # Exclusive creation also prevents concurrent runs from replacing an identity.
        with path.open('x', encoding='utf-8') as file:
            identity = {'app_id': str(uuid.uuid4()),
                        'hwid': hashlib.sha256(secrets.token_bytes(32)).hexdigest(),
                        'device': 'BLACKTEMPLE-Test-Android'}
            json.dump(identity, file, indent=2)
        try:
            path.chmod(0o600)
        except OSError:
            pass
    except FileExistsError:
        try:
            identity = json.loads(path.read_text(encoding='utf-8'))
        except (ValueError, UnicodeError):
            raise ExportError('Файл идентификатора повреждён; не удаляйте его без необходимости.') from None
    if not isinstance(identity, dict) or any(
        not isinstance(identity.get(k), str) or not identity[k] or
        any(ord(c) < 32 or ord(c) > 126 for c in identity[k])
        for k in ('app_id', 'hwid', 'device')
    ):
        raise ExportError('Некорректный файл идентификатора устройства.')
    return identity


def signing_key(listing: Path | None = None) -> str:
    key = os.environ.get('BLACKTEMPLE_SIGNING_KEY')
    if key:
        return key
    if listing is None:
        return BUILTIN_SIGNING_KEY
    try:
        match = re.search(r'0x6cb980: r2 = "([^"\r\n]+)"', listing.read_text(encoding='utf-8'))
    except OSError:
        match = None
    if not match:
        raise ExportError('Не найден HMAC-ключ в явно указанном листинге.')
    return match.group(1)


def signed_headers(url: str, identity: dict, key: str, timestamp: int) -> dict:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username or
            parsed.password or parsed.fragment or parsed.query or
            any(ord(c) <= 32 or ord(c) == 127 for c in url)):
        raise ExportError('Нужна HTTPS-ссылка без логина, query-параметров и fragment.')
    suffix = parsed.path.rsplit('/', 1)[-1]
    if not suffix:
        raise ExportError('В ссылке отсутствует токен подписки.')
    message = f"GET\n/sub/{suffix}\n{timestamp}\n{identity['app_id']}"
    return {'User-Agent': 'Blacktemple/1.3.16', 'Accept': 'application/json',
            'device': identity['device'], 'X-hwid': identity['hwid'],
            'X-App-Id': identity['app_id'], 'X-Timestamp': str(timestamp),
            'X-Signature': hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()}


def fetch_subscription(url: str, identity: dict, key: str, timeout: float) -> bytes:
    headers = signed_headers(url, identity, key, int(time.time()))
    request = urllib.request.Request(url, headers=headers, method='GET')
    try:
        with urllib.request.build_opener(NoRedirect).open(request, timeout=timeout) as response:
            if response.status != 200:
                raise ExportError(f'Неожиданный HTTP-статус: {response.status}.')
            body = response.read(MAX_BODY + 1)
    except urllib.error.HTTPError as error:
        code = error.code
        error.close()
        raise ExportError(f'HTTP {code}; перенаправления не выполняются.') from None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
        raise ExportError('Ошибка HTTPS-запроса. Проверьте сеть, ссылку и системное время.') from None
    if len(body) > MAX_BODY:
        raise ExportError('Ответ превышает лимит 4 MiB.')
    return body


def parse_subscription(body: bytes) -> list[dict]:
    if len(body) > MAX_BODY:
        raise ExportError('Ответ превышает лимит 4 MiB.')
    try:
        text = body.decode('utf-8-sig').strip()
    except UnicodeError:
        raise ExportError('Ответ не является UTF-8.') from None
    try:
        data = json.loads(text)
    except ValueError:
        if not text.startswith('vless://'):
            try:
                raw = ''.join(text.split())
                text = base64.b64decode(raw + '=' * (-len(raw) % 4), altchars=b'-_', validate=True).decode('utf-8')
            except (ValueError, UnicodeError):
                raise ExportError('Ожидался JSON, список VLESS или Base64-подписка.') from None
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines or any(not line.startswith('vless://') for line in lines):
            raise ExportError('Ответ содержит не только VLESS-записи.')
        data = {'servers': [{'key': line} for line in lines]}
    if not isinstance(data, dict) or data.get('status', 'success') != 'success':
        raise ExportError('Сервис не вернул успешную подписку.')
    servers = data.get('servers')
    if not isinstance(servers, list) or not servers:
        raise ExportError('В подписке нет серверов.')
    result = []
    for index, server in enumerate(servers, 1):
        if not isinstance(server, dict) or not isinstance(server.get('key'), str):
            raise ExportError(f'У записи №{index} отсутствует VLESS-ключ.')
        result.append(server)
    return result


def make_profile(server: dict, index: int) -> tuple[dict, dict]:
    uri = server['key'].strip()
    try:
        u = urllib.parse.urlsplit(uri)
        if u.scheme != 'vless' or not u.hostname or not u.port or not u.username or u.password:
            raise ValueError()
        user_id = str(uuid.UUID(urllib.parse.unquote(u.username)))
        host, port = u.hostname, u.port
        try:
            if ipaddress.ip_address(host).is_loopback or ipaddress.ip_address(host).is_unspecified:
                raise ExportError('Получена localhost-заглушка вместо серверов подписки.')
        except ValueError:
            if host.lower() == 'localhost':
                raise ExportError('Получена localhost-заглушка вместо серверов подписки.')
        query = urllib.parse.parse_qs(u.query, keep_blank_values=True)
        if any(len(values) != 1 for values in query.values()):
            raise ValueError()
    except (ValueError, AttributeError):
        raise ExportError(f'Некорректный VLESS URI в записи №{index}.') from None
    q = {k: v[0] for k, v in query.items()}
    allowed = {'type', 'security', 'encryption', 'flow', 'sni', 'fp', 'alpn', 'pbk',
               'sid', 'spx', 'host', 'path', 'headerType', 'serviceName', 'mode',
               'authority', 'extra', 'allowInsecure'}
    if set(q) - allowed:
        raise ExportError(f'Запись №{index}: неизвестные параметры VLESS; экспорт остановлен без потери настроек.')
    network = q.get('type', 'tcp')
    security = q.get('security', 'none')
    if network not in ('tcp', 'raw', 'ws', 'grpc', 'xhttp', 'httpupgrade'):
        raise ExportError(f'Запись №{index}: неподдерживаемый транспорт.')
    if security not in ('none', 'tls', 'reality') or q.get('encryption', 'none') != 'none':
        raise ExportError(f'Запись №{index}: неподдерживаемое шифрование.')
    stream = {'network': network, 'security': security}
    if security in ('tls', 'reality'):
        settings = {}
        for source, target in [('sni', 'serverName'), ('fp', 'fingerprint')]:
            if q.get(source):
                settings[target] = q[source]
        if security == 'tls':
            if q.get('alpn'):
                settings['alpn'] = q['alpn'].split(',')
            if q.get('allowInsecure'):
                if q['allowInsecure'].lower() not in ('0', '1', 'true', 'false'):
                    raise ExportError(f'Запись №{index}: некорректный allowInsecure.')
                settings['allowInsecure'] = q['allowInsecure'].lower() in ('1', 'true')
        else:
            if not q.get('pbk'):
                raise ExportError(f'Запись №{index}: отсутствует публичный ключ Reality.')
            settings.update(publicKey=q['pbk'], shortId=q.get('sid', ''))
            if q.get('spx'):
                settings['spiderX'] = q['spx']
        stream[security + 'Settings'] = settings
    header_type = q.get('headerType') or 'none'
    if network in ('tcp', 'raw'):
        if header_type == 'http':
            request = {'path': q.get('path', '/').split(',')}
            if q.get('host'):
                request['headers'] = {'Host': q['host'].split(',')}
            stream['tcpSettings' if network == 'tcp' else 'rawSettings'] = {
                'header': {'type': 'http', 'request': request}}
        elif header_type != 'none':
            raise ExportError(f'Запись №{index}: неподдерживаемая маскировка TCP.')
    elif network in ('ws', 'httpupgrade'):
        settings = {'path': q.get('path', '/')}
        if q.get('host'):
            if network == 'ws':
                settings['headers'] = {'Host': q['host']}
            else:
                settings['host'] = q['host']
        stream[network + 'Settings'] = settings
    elif network == 'grpc':
        mode = q.get('mode', 'gun')
        if mode not in ('gun', 'multi'):
            raise ExportError(f'Запись №{index}: неизвестный режим gRPC.')
        stream['grpcSettings'] = {'serviceName': q.get('serviceName', ''), 'multiMode': mode == 'multi'}
        if q.get('authority'):
            stream['grpcSettings']['authority'] = q['authority']
    elif network == 'xhttp':
        settings = {'path': q.get('path', '/'), 'host': q.get('host', ''), 'mode': q.get('mode', 'auto')}
        if q.get('extra'):
            try:
                extra = json.loads(q['extra'])
                if not isinstance(extra, dict):
                    raise ValueError()
            except ValueError:
                raise ExportError(f'Запись №{index}: некорректный XHTTP extra.') from None
            settings['extra'] = extra
        stream['xhttpSettings'] = settings
    name = urllib.parse.unquote(u.fragment) or str(server.get('country') or server.get('panel_name') or f'Сервер {index}')
    labels = []
    for field in ('country', 'server_class'):
        label = str(server.get(field) or '').strip()
        if label and label.casefold() not in {value.casefold() for value in labels}:
            labels.append(label)
    prefix = '[' + ' · '.join(labels) + '] '
    if labels and not name.startswith(prefix):
        # A country-only fallback name already carries this information.
        if len(labels) != 1 or name.casefold() != labels[0].casefold():
            name = prefix + name
    if labels:
        # Only the display fragment changes; preserve all connection parameters verbatim.
        uri = uri.split('#', 1)[0] + '#' + urllib.parse.quote(name, safe='')
    user = {'id': user_id, 'encryption': 'none'}
    if q.get('flow'):
        user['flow'] = q['flow']
    profile = {
        'remarks': name,
        'log': {'loglevel': 'warning'},
        'inbounds': [{'tag': 'socks', 'listen': '127.0.0.1', 'port': 10808,
                      'protocol': 'socks', 'settings': {'auth': 'noauth', 'udp': True}}],
        'outbounds': [{'tag': 'proxy', 'protocol': 'vless',
                       'settings': {'vnext': [{'address': host, 'port': port, 'users': [user]}]},
                       'streamSettings': stream},
                      {'tag': 'direct', 'protocol': 'freedom'},
                      {'tag': 'block', 'protocol': 'blackhole'}],
    }
    item = {'name': name, 'uri': uri, 'host': host, 'port': port,
            'country': str(server.get('country') or ''),
            'category': str(server.get('server_class') or ''),
            'transport': network, 'security': security}
    return profile, item


def qr_svg(uri: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg
        from qrcode.exceptions import DataOverflowError
    except ImportError:
        raise ExportError('Установите зависимость: python -m pip install -r requirements-subscription.txt') from None
    try:
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=4)
        qr.add_data(uri.encode('utf-8'))
        qr.make(fit=True)
        image = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
        buf = io.BytesIO()
        image.save(buf)
        return buf.getvalue().decode('utf-8').split('?>')[-1].strip()
    except DataOverflowError:
        raise ExportError('VLESS-ключ слишком длинный для QR-кода.') from None


def render_html(items: list[dict]) -> str:
    cards = []
    for index, item in enumerate(items, 1):
        escape = lambda value: html.escape(str(value), quote=True)
        meta = ' · '.join(filter(None, [item['country'], item['category'],
                                       item['transport'] + '/' + item['security'],
                                       f"{item['host']}:{item['port']}"]))
        cards.append(f'''<article class="card">
<h2>{index}. {escape(item['name'])}</h2><p class="meta">{escape(meta)}</p>
<textarea aria-label="VLESS-ключ" readonly spellcheck="false">{escape(item['uri'])}</textarea>
<div class="actions"><button class="copy">Копировать ключ</button>
<button class="show" aria-expanded="false">Показать QR</button>
<a href="{escape(item['uri'])}">Открыть в клиенте</a></div>
<div class="qr" hidden>{qr_svg(item['uri'])}<p>Сканируйте в VPN-клиенте</p></div>
</article>''')
    return '''<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>VLESS — выбор сервера</title><style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101522;color:#edf1fa}
body{max-width:1000px;margin:auto;padding:24px}h1{margin-bottom:8px}p{line-height:1.5}
.notice,.meta{color:#aebbd1}input,textarea{box-sizing:border-box;width:100%;border:1px solid #465675;border-radius:8px;background:#101522;color:inherit;padding:12px;font:inherit}
input{margin:12px 0}textarea{font:13px monospace;min-height:88px;resize:vertical;overflow-wrap:anywhere}
.card{background:#1a2437;border:1px solid #35445f;border-radius:14px;padding:20px;margin:16px 0}h2{font-size:19px;overflow-wrap:anywhere}.meta{overflow-wrap:anywhere}
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-top:12px}
button,.actions a{font:inherit;cursor:pointer;border:1px solid #6883b7;border-radius:8px;padding:10px 14px;background:#273d63;color:#fff;text-decoration:none}
button:focus-visible,a:focus-visible{outline:3px solid #9cc6ff}.qr{margin-top:18px;text-align:center}.qr svg{background:#fff;width:100%;max-width:420px;height:auto}.qr p{color:#aebbd1}
[hidden]{display:none!important}#status{min-height:24px;color:#a9dbb4}footer{margin-top:30px;color:#aebbd1}
</style></head><body><h1>VLESS — выбор сервера</h1>
<p class="notice">Локальная страница: ключи и QR не отправляются сторонним сервисам.
Этот файл содержит секреты подписки — не публикуйте его.</p>
<p>Выберите сервер, скопируйте ключ либо покажите QR для импорта в клиент.</p>
<label for="search">Поиск по названию, стране, классу и адресу</label>
<input id="search" type="search" placeholder="Название или страна…">
<div id="count"></div><div id="status" role="status" aria-live="polite"></div>
<main>''' + '\n'.join(cards) + '''</main><noscript>Для кнопок и поиска включите JavaScript. Ключи можно выделить и скопировать вручную.</noscript>
<footer>JSON рядом с этой страницей — массив отдельных профилей Xray, а не универсальный формат всех клиентов.
Если клиент не поддерживает такой импорт, используйте VLESS-ключ или QR. Подключения к серверам не проверялись.</footer>
<script>
const cards = [...document.querySelectorAll('.card')];
const status = document.getElementById('status');
const count = document.getElementById('count');
function filter() {
 const term = document.getElementById('search').value.toLocaleLowerCase();
 let visible = 0;
 for (const card of cards) {
  const text = card.querySelector('h2').textContent + ' ' + card.querySelector('.meta').textContent;
  card.hidden = !text.toLocaleLowerCase().includes(term);
  if (!card.hidden) visible++;
 }
 count.textContent = `Серверов: ${visible} из ${cards.length}`;
}
document.getElementById('search').addEventListener('input', filter); filter();
for (const card of cards) {
 card.querySelector('.show').addEventListener('click', (event) => {
  const qr = card.querySelector('.qr'); qr.hidden = !qr.hidden;
  event.currentTarget.setAttribute('aria-expanded', String(!qr.hidden));
  event.currentTarget.textContent = qr.hidden ? 'Показать QR' : 'Скрыть QR';
 });
 card.querySelector('.copy').addEventListener('click', async () => {
  const text = card.querySelector('textarea');
  try {
   if (!navigator.clipboard) throw new Error();
   await navigator.clipboard.writeText(text.value);
   status.textContent = 'Ключ скопирован.';
  } catch (_) {
   text.focus(); text.select(); text.setSelectionRange(0, text.value.length);
   status.textContent = document.execCommand('copy') ? 'Ключ скопирован.' : 'Ключ выделен. Нажмите Ctrl+C / Cmd+C.';
  }
 });
}
</script></body></html>'''


def export(body: bytes, prefix: Path) -> int:
    profiles, items = [], []
    for index, server in enumerate(parse_subscription(body), 1):
        profile, item = make_profile(server, index)
        profiles.append(profile)
        items.append(item)
    # Generate both completely before writing, so parsing/QR errors leave no partial export.
    json_text = json.dumps(profiles, ensure_ascii=False, indent=2) + '\n'
    html_text = render_html(items)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    for suffix, content in (('.json', json_text), ('.html', html_text)):
        path = Path(str(prefix) + suffix)
        path.write_text(content, encoding='utf-8')
        try:
            path.chmod(0o600)
        except OSError:
            pass
    return len(items)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument('url', nargs='?', help='HTTPS-ссылка подписки (без аргумента — скрытый ввод)')
    source.add_argument('--input', type=Path, help='Сохранённый ответ; без сетевых запросов')
    parser.add_argument('-o', '--output', type=Path, default=Path('output/subscription'), help='Префикс двух выходных файлов')
    parser.add_argument('--identity', type=Path, default=default_identity_path(), help='Файл идентификатора (по умолчанию создаётся в пользовательской папке настроек)')
    parser.add_argument('--listing', type=Path, help='Необязательная замена встроенного HMAC-ключа из листинга')
    parser.add_argument('--timeout', type=float, default=30)
    args = parser.parse_args(argv)
    try:
        if args.timeout <= 0:
            raise ExportError('Таймаут должен быть положительным.')
        if args.input:
            with args.input.open('rb') as file:
                body = file.read(MAX_BODY + 1)
        else:
            import getpass
            url = args.url or getpass.getpass('Ссылка подписки (скрытый ввод): ')
            # Check URL before creating a new identity.
            key = signing_key(args.listing)
            signed_headers(url, {'app_id': '', 'hwid': '', 'device': ''}, key, 0)
            body = fetch_subscription(url, load_identity(args.identity), key, args.timeout)
        count = export(body, args.output)
    except ExportError as error:
        print(f'Ошибка: {error}', file=sys.stderr)
        return 1
    except (OSError, ValueError, UnicodeError):
        print('Ошибка чтения/записи файла или некорректные входные данные. Секреты не выведены.', file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print('Отменено.', file=sys.stderr)
        return 1
    print(f'Экспортировано серверов: {count}')
    print(f'JSON (Xray): {args.output}.json\nHTML: {args.output}.html')
    print('Файлы содержат приватные ключи доступа. VPN-соединения не проверялись.')
    return 0


if __name__ == '__main__':
    sys.exit(main())

import ipaddress
import re
import socket
import ssl
from datetime import datetime, timezone
from difflib import SequenceMatcher
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


def parse_rdap_datetime(value):
    if not value or not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    try:
        if raw.endswith('Z'):
            raw = raw[:-1] + '+00:00'
        parsed = datetime.fromisoformat(raw)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except Exception:
        return None


def is_private_or_local_host(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return host in {'localhost'} or host.endswith('.local')


def domain_age_days(domain_name):
    try:
        rdap_url = f'https://rdap.org/domain/{domain_name}'
        response = requests.get(rdap_url, timeout=5)
        if response.status_code != 200:
            return None, None

        payload = response.json()
        events = payload.get('events', []) if isinstance(payload, dict) else []

        created_at = None
        expires_at = None
        for event in events:
            action = str(event.get('eventAction', '')).lower()
            event_date = parse_rdap_datetime(event.get('eventDate'))
            if not event_date:
                continue

            if action in {'registration', 'registered'} and created_at is None:
                created_at = event_date
            if action in {'expiration', 'expired'} and expires_at is None:
                expires_at = event_date

        if created_at is None:
            return None, None

        now = datetime.now(timezone.utc)
        age_days = max(0, (now - created_at).days)

        reg_len_days = None
        if expires_at is not None and expires_at > created_at:
            reg_len_days = (expires_at - created_at).days

        return age_days, reg_len_days
    except Exception:
        return None, None


def ssl_certificate_status(host, timeout_seconds=4):
    if not host or is_private_or_local_host(host):
        return {
            'has_ssl': False,
            'ssl_valid': False,
            'ssl_issuer': None,
            'ssl_valid_until': None,
            'ssl_error': 'Skipped for local/private host',
        }

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout_seconds) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()

        not_after = cert.get('notAfter')
        expires_at = None
        if not_after:
            expires_at = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)

        issuer_pairs = cert.get('issuer', [])
        issuer_parts = []
        for item in issuer_pairs:
            for key, value in item:
                if key in {'organizationName', 'commonName'}:
                    issuer_parts.append(str(value))
        issuer_text = ', '.join(issuer_parts) if issuer_parts else None

        now = datetime.now(timezone.utc)
        ssl_valid = expires_at is None or expires_at >= now

        return {
            'has_ssl': True,
            'ssl_valid': ssl_valid,
            'ssl_issuer': issuer_text,
            'ssl_valid_until': expires_at.isoformat() if expires_at else None,
            'ssl_error': None,
        }
    except Exception as exc:
        return {
            'has_ssl': False,
            'ssl_valid': False,
            'ssl_issuer': None,
            'ssl_valid_until': None,
            'ssl_error': str(exc),
        }


def safe_get_page(url):
    try:
        headers = {
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36'
            )
        }
        parsed = urlparse(url)
        host = parsed.netloc.split(':')[0].lower()
        if is_private_or_local_host(host):
            return None, None, url, 0, True

        response = requests.get(url, timeout=3, headers=headers, allow_redirects=True)
        if 'text/html' not in response.headers.get('Content-Type', ''):
            return None, None, response.url, len(response.history), False
        soup = BeautifulSoup(response.text, 'html.parser')
        return response.text, soup, response.url, len(response.history), False
    except Exception:
        return None, None, url, 0, True


def is_same_domain(resource_url, base_domain):
    parsed = urlparse(resource_url)
    if not parsed.netloc:
        return True
    host = parsed.netloc.split(':')[0].lower()
    base = base_domain.lower()
    return host == base or host.endswith('.' + base)


def looks_like_brand_typo(domain_name, brand_roots):
    labels = [label for label in domain_name.split('.') if label]
    if not labels:
        return False

    candidate = labels[-2] if len(labels) >= 2 else labels[0]
    cleaned = re.sub(r'[^a-z0-9]', '', candidate.lower())
    if not cleaned:
        return False

    for brand in brand_roots:
        if cleaned == brand:
            continue

        ratio = SequenceMatcher(None, cleaned, brand).ratio()
        close_length = abs(len(cleaned) - len(brand)) <= 2
        same_prefix = cleaned[:3] == brand[:3]

        if close_length and same_prefix and ratio >= 0.72:
            return True

    return False


def is_known_shortener(domain_name):
    shortener_hosts = {
        'bit.ly', 'tinyurl.com', 'short.link', 'is.gd', 'ow.ly', 'goo.gl',
        'cutt.ly', 't.co', 'rb.gy'
    }
    host = (domain_name or '').lower().split(':')[0]
    return any(host == short or host.endswith('.' + short) for short in shortener_hosts)


def extract_features(url):
    features = []

    try:
        url_lower = url.lower()

        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        domain_name = domain.split(':')[0] if ':' in domain else domain
        html, soup, final_url, redirect_count, fetch_failed = safe_get_page(url)

        try:
            ipaddress.ip_address(domain_name)
            features.append(-1)
        except ValueError:
            features.append(1)

        url_len = len(url)
        if url_len < 54:
            features.append(1)
        elif url_len <= 75:
            features.append(0)
        else:
            features.append(-1)

        features.append(-1 if is_known_shortener(domain_name) else 1)
        features.append(-1 if '@' in url else 1)
        features.append(-1 if url.rfind('//') > 7 else 1)
        features.append(-1 if '-' in domain_name else 1)

        dot_count = domain_name.count('.')
        if dot_count <= 1:
            features.append(1)
        elif dot_count == 2:
            features.append(0)
        else:
            features.append(-1)

        features.append(1 if parsed.scheme == 'https' else -1)

        age_days, reg_len_days = domain_age_days(domain_name)
        if reg_len_days is None:
            labels = domain_name.replace('-', '').split('.')
            effective_len = len(''.join(labels[:-1])) if len(labels) > 1 else len(domain_name)
            features.append(1 if 6 <= effective_len <= 30 else 0)
        else:
            features.append(1 if reg_len_days >= 365 else -1)

        favicon_feature = 0
        if soup:
            icon_link = soup.find('link', rel=lambda x: x and 'icon' in str(x).lower())
            if icon_link and icon_link.get('href'):
                fav_url = urljoin(final_url, icon_link.get('href'))
                favicon_feature = 1 if is_same_domain(fav_url, domain_name) else -1
            else:
                favicon_feature = 1
        features.append(favicon_feature)

        if parsed.port is None:
            features.append(1)
        else:
            features.append(1 if parsed.port in {80, 443} else -1)

        features.append(-1 if 'https' in domain_name else 1)

        request_feature = 0
        if soup:
            tags = soup.find_all(['img', 'audio', 'embed', 'iframe', 'source'])
            total = len(tags)
            external = 0
            for tag in tags:
                src = tag.get('src')
                if not src:
                    continue
                abs_src = urljoin(final_url, src)
                if not is_same_domain(abs_src, domain_name):
                    external += 1
            if total > 0:
                ratio = external / total
                if ratio < 0.22:
                    request_feature = 1
                elif ratio <= 0.61:
                    request_feature = 0
                else:
                    request_feature = -1
        features.append(request_feature)

        anchor_feature = 0
        if soup:
            anchors = soup.find_all('a', href=True)
            total = len(anchors)
            unsafe = 0
            for a in anchors:
                href = a.get('href', '').strip().lower()
                if href in {'', '#', '#content', '#skip', 'javascript:void(0)'}:
                    unsafe += 1
                    continue
                abs_href = urljoin(final_url, href)
                if not is_same_domain(abs_href, domain_name):
                    unsafe += 1
            if total > 0:
                ratio = unsafe / total
                if ratio < 0.31:
                    anchor_feature = 1
                elif ratio <= 0.67:
                    anchor_feature = 0
                else:
                    anchor_feature = -1
        features.append(anchor_feature)

        script_link_feature = 0
        if soup:
            refs = []
            refs.extend([l.get('href') for l in soup.find_all('link', href=True)])
            refs.extend([s.get('src') for s in soup.find_all('script', src=True)])
            total = len(refs)
            external = 0
            for ref in refs:
                abs_ref = urljoin(final_url, ref)
                if not is_same_domain(abs_ref, domain_name):
                    external += 1
            if total > 0:
                ratio = external / total
                if ratio < 0.17:
                    script_link_feature = 1
                elif ratio <= 0.81:
                    script_link_feature = 0
                else:
                    script_link_feature = -1
        features.append(script_link_feature)

        sfh_feature = 1
        if soup:
            forms = soup.find_all('form')
            if forms:
                form = forms[0]
                action = (form.get('action') or '').strip().lower()
                if action in {'', 'about:blank'}:
                    sfh_feature = -1
                else:
                    abs_action = urljoin(final_url, action)
                    sfh_feature = 1 if is_same_domain(abs_action, domain_name) else 0
        features.append(sfh_feature)

        features.append(-1 if 'mailto:' in url_lower or 'mail()' in (html or '').lower() else 1)
        features.append(1 if domain_name in urlparse(final_url).netloc.lower() else -1)

        if redirect_count <= 1:
            features.append(1)
        elif redirect_count <= 4:
            features.append(0)
        else:
            features.append(-1)

        page_text = (html or '').lower()
        status_bar_patterns = ['onmouseover', 'window.status', 'status=']
        features.append(-1 if all(p in page_text for p in status_bar_patterns[:2]) or status_bar_patterns[2] in page_text else 1)
        features.append(-1 if 'event.button==2' in page_text or 'contextmenu' in page_text else 1)
        features.append(-1 if 'alert(' in page_text or 'window.open(' in page_text else 1)
        features.append(-1 if '<iframe' in page_text or 'frameborder' in page_text else 1)

        if age_days is None:
            entropy_like = len(set(domain_name.replace('.', '').replace('-', '')))
            features.append(-1 if entropy_like > 18 else 0)
        else:
            features.append(1 if age_days >= 180 else -1)

        domain_resolves = False
        try:
            socket.gethostbyname(domain_name)
            domain_resolves = True
            features.append(1 if age_days is None or age_days >= 180 else -1)
        except Exception:
            features.append(-1)

        if not domain_resolves or fetch_failed:
            features.append(-1)
        elif soup:
            features.append(1 if len(soup.find_all('a', href=True)) > 10 else 0)
        else:
            features.append(0)

        features.append(-1 if not domain_resolves else 0)
        features.append(-1 if (not domain_resolves or fetch_failed) else 0)

        if soup:
            backlink_signal = len(soup.find_all('a', href=True))
            if backlink_signal == 0:
                features.append(-1)
            elif backlink_signal <= 2:
                features.append(0)
            else:
                features.append(1)
        else:
            features.append(-1 if (not domain_resolves or fetch_failed) else 0)

        suspicious_tlds = ('.tk', '.ml', '.ga', '.cf', '.gq')
        features.append(-1 if domain_name.endswith(suspicious_tlds) else 1)

    except Exception as e:
        print(f'Error extracting features: {e}')
        features = [0] * 30

    return features

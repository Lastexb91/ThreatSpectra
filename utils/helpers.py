import os
import re
import smtplib
import ssl
from io import BytesIO
from email.message import EmailMessage
from urllib.parse import urlparse

import numpy as np
from PIL import Image, ImageFilter, ImageOps

try:
    import zxingcpp
except Exception:
    zxingcpp = None

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
except Exception:
    pyzbar_decode = None


def load_env_file(file_path='.env'):
    try:
        if not os.path.exists(file_path):
            return

        with open(file_path, 'r', encoding='utf-8') as env_file:
            for raw_line in env_file:
                line = raw_line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue

                key, value = line.split('=', 1)
                key = key.strip().lstrip('\ufeff')
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as exc:
        print(f'Warning: Could not load .env file: {exc}')


def is_valid_url(url):
    try:
        result = urlparse(url)
        if result.netloc or (not result.scheme and '.' in url):
            return True
        return False
    except Exception:
        return False


def extract_urls(text):
    raw_urls = re.findall(r'https?://[^\s<>")\]]+', str(text or ''))
    return [url.rstrip('.,;:!?)') for url in raw_urls]


def extract_domains(text):
    domains = []
    for url in extract_urls(text):
        try:
            host = urlparse(url).netloc.lower().split(':')[0].strip()
            if host:
                domains.append(host)
        except Exception:
            continue
    return domains


def extract_qr_urls_from_upload(uploaded_file):
    file_bytes = uploaded_file.read()
    if not file_bytes:
        return []

    try:
        image = Image.open(BytesIO(file_bytes)).convert('RGB')
    except Exception:
        return []

    def _otsu_threshold(gray_array):
        histogram = np.bincount(gray_array.ravel(), minlength=256).astype(np.float64)
        total = gray_array.size
        if total == 0:
            return 0

        weighted_total = np.dot(np.arange(256), histogram)
        cumulative_weight = 0.0
        cumulative_mean = 0.0
        max_between_class_variance = -1.0
        threshold = 0

        for value in range(256):
            cumulative_weight += histogram[value]
            if cumulative_weight == 0:
                continue

            remaining_weight = total - cumulative_weight
            if remaining_weight == 0:
                break

            cumulative_mean += value * histogram[value]
            mean_background = cumulative_mean / cumulative_weight
            mean_foreground = (weighted_total - cumulative_mean) / remaining_weight

            between_class_variance = (
                cumulative_weight
                * remaining_weight
                * (mean_background - mean_foreground) ** 2
            )
            if between_class_variance > max_between_class_variance:
                max_between_class_variance = between_class_variance
                threshold = value

        return threshold

    def _decode_zxing(candidate_image):
        if zxingcpp is None:
            return []

        decoded = []
        try:
            results = zxingcpp.read_barcodes(np.asarray(candidate_image))
        except Exception:
            return decoded

        for result in results or []:
            value = getattr(result, 'text', '')
            if isinstance(value, str) and value.strip():
                decoded.append(value.strip())
        return decoded

    def _decode_pyzbar(candidate_image):
        if pyzbar_decode is None:
            return []

        decoded = []
        try:
            results = pyzbar_decode(candidate_image)
        except Exception:
            return decoded

        for result in results or []:
            raw_data = getattr(result, 'data', b'')
            if isinstance(raw_data, bytes):
                value = raw_data.decode('utf-8', errors='ignore').strip()
            else:
                value = str(raw_data).strip()
            if value:
                decoded.append(value)
        return decoded

    def _decode_from_candidate(candidate):
        decoded = _decode_zxing(candidate)
        if decoded:
            return decoded
        return _decode_pyzbar(candidate)

    gray = ImageOps.grayscale(image)
    enhanced_gray = ImageOps.autocontrast(gray)
    smoothed_gray = enhanced_gray.filter(ImageFilter.MedianFilter(size=3))

    gray_array = np.asarray(smoothed_gray, dtype=np.uint8)
    otsu_cutoff = _otsu_threshold(gray_array)
    otsu_binary_array = np.where(gray_array > otsu_cutoff, 255, 0).astype(np.uint8)
    otsu_binary = Image.fromarray(otsu_binary_array, mode='L')
    inverted = ImageOps.invert(otsu_binary)

    candidates = [image, gray, enhanced_gray, smoothed_gray, otsu_binary, inverted]

    for source in (smoothed_gray, otsu_binary, inverted):
        for scale in (2.0, 3.0):
            new_size = (max(1, int(source.width * scale)), max(1, int(source.height * scale)))
            resized = source.resize(new_size, Image.Resampling.BICUBIC)
            bordered = ImageOps.expand(resized, border=24, fill=255)
            candidates.append(resized)
            candidates.append(bordered)

    rotated_candidates = []
    for candidate in candidates:
        rotated_candidates.append(candidate)
        rotated_candidates.append(candidate.rotate(90, expand=True))
        rotated_candidates.append(candidate.rotate(180, expand=True))
        rotated_candidates.append(candidate.rotate(270, expand=True))

    decoded_values = []
    for candidate in rotated_candidates:
        decoded_values.extend(_decode_from_candidate(candidate))
        if decoded_values:
            break

    unique_values = []
    seen = set()
    for value in decoded_values:
        if value not in seen:
            unique_values.append(value)
            seen.add(value)

    return unique_values


def load_contact_mail_settings():
    return {
        'host': os.getenv('CONTACT_SMTP_HOST', '').strip(),
        'port': int(os.getenv('CONTACT_SMTP_PORT', '587')),
        'username': os.getenv('CONTACT_SMTP_USERNAME', '').strip(),
        'password': os.getenv('CONTACT_SMTP_PASSWORD', '').strip(),
        'to_email': os.getenv('CONTACT_TO_EMAIL', '').strip(),
        'from_email': os.getenv('CONTACT_FROM_EMAIL', '').strip(),
        'use_tls': os.getenv('CONTACT_SMTP_USE_TLS', 'true').strip().lower() in {'1', 'true', 'yes', 'on'},
    }


def send_contact_email(name, sender_email, message_text):
    settings = load_contact_mail_settings()

    missing = []
    if not settings['host']:
        missing.append('CONTACT_SMTP_HOST')
    if not settings['username']:
        missing.append('CONTACT_SMTP_USERNAME')
    if not settings['password']:
        missing.append('CONTACT_SMTP_PASSWORD')

    to_email = settings['to_email'] or settings['username']
    from_email = settings['from_email'] or settings['username']

    if missing:
        raise RuntimeError('Missing SMTP config: ' + ', '.join(missing))

    msg = EmailMessage()
    msg['Subject'] = 'New Contact Message - ThreatSpectra'
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Reply-To'] = sender_email
    msg.set_content(
        'You received a new message from the ThreatSpectra contact form.\n\n'
        f'Name: {name}\n'
        f'Email: {sender_email}\n\n'
        'Message:\n'
        f'{message_text}\n'
    )

    with smtplib.SMTP(settings['host'], settings['port'], timeout=15) as server:
        if settings['use_tls']:
            server.starttls(context=ssl.create_default_context())
        server.login(settings['username'], settings['password'])
        server.send_message(msg)

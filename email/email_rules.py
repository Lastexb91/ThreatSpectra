import re
from urllib.parse import urlparse

from email_features import TRUSTED_DOMAINS
from utils.helpers import extract_domains, extract_urls


def detect_malicious_intent(text):
    text = str(text or '').lower()

    negated_sensitive_instruction = bool(
        re.search(r"(do\s*not|never|don't)\s+(enter|submit|provide|shar(?:e|ing)|repl(?:y|ying)|send).{0,50}(otp|password|pin|cvv|credential|credentials|login detail(?:s)?|account detail(?:s)?)", text)
    )
    sensitive_request = bool(
        re.search(r'(enter|submit|provide|shar(?:e|ing)|repl(?:y|ying)|send).{0,50}(otp|password|pin|cvv|credential|credentials|login credentials|login detail(?:s)?|account detail(?:s)?)', text)
    )

    if sensitive_request and not negated_sensitive_instruction:
        return True

    if re.search(r'(urgent|immediately|within \d+ (hours|minutes)|failure to respond|suspend|suspension|restrict|restriction).{0,40}(verify|login|update|confirm)', text):
        return True
    if re.search(r'(verify|login|update|confirm).{0,40}(account|details|identity).{0,50}(urgent|immediately|within \d+|suspend|suspension|restrict|restriction|failure)', text):
        return True

    return False


def is_trusted_domain(domain):
    d = str(domain or '').lower().strip()
    return d in TRUSTED_DOMAINS or any(d.endswith('.' + trusted) for trusted in TRUSTED_DOMAINS)


def contains_phishing_url(urls):
    for raw_url in urls:
        try:
            host = urlparse(raw_url).netloc.lower().split(':')[0].strip()
            if is_trusted_domain(host):
                continue
            from url.url_predict import build_prediction_response
            website_result = build_prediction_response(raw_url)
            if website_result.get('result') == 'Phishing':
                return True
        except Exception:
            continue
    return False


def extract_email_urls(text):
    return extract_urls(text)


def extract_email_domains(text):
    return extract_domains(text)

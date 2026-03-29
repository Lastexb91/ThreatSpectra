import re

TRUSTED_DOMAINS = {
    'bankofamerica.com',
    'paypal.com',
    'amazon.com',
    'google.com',
    'microsoft.com',
}


def extract_email_features(email_text):
    processed = str(email_text or '').lower().strip()
    words = re.findall(r"[a-zA-Z0-9']+", processed)
    unique_words = set(words)

    stop_words = {
        'a', 'an', 'and', 'are', 'as', 'at', 'be', 'but', 'by', 'for', 'from', 'if',
        'in', 'into', 'is', 'it', 'no', 'not', 'of', 'on', 'or', 'such', 'that', 'the',
        'their', 'then', 'there', 'these', 'they', 'this', 'to', 'was', 'will', 'with'
    }
    num_stopwords = sum(1 for token in words if token in stop_words)

    link_matches = re.findall(r'(https?://\S+|www\.\S+)', processed)
    num_links = len(link_matches)

    url_domains = re.findall(r'https?://([^\s/]+)', processed)
    email_domains = re.findall(r'\b[a-z0-9._%+-]+@([a-z0-9.-]+\.[a-z]{2,})\b', processed)
    unique_domains = {
        domain.lower().strip('.,;:!?)(')
        for domain in (url_domains + email_domains)
        if domain
    }

    email_matches = re.findall(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', processed)

    urgent_keywords = {'urgent', 'verify', 'password', 'otp', 'pin', 'cvv'}
    num_urgent_keywords = sum(1 for token in words if token in urgent_keywords)

    return {
        'num_words': len(words),
        'num_unique_words': len(unique_words),
        'num_stopwords': num_stopwords,
        'num_links': num_links,
        'num_unique_domains': len(unique_domains),
        'num_email_addresses': len(email_matches),
        'num_spelling_errors': 0,
        'num_urgent_keywords': num_urgent_keywords,
    }

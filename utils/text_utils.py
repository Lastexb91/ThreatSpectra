import re


def preprocess_email_text(text):
    return str(text or '').lower().strip()


def is_low_information_text(text):
    processed = preprocess_email_text(text)
    if not processed:
        return True

    tokens = re.findall(r"[a-z0-9']+", processed)
    if len(tokens) < 3:
        return True

    has_url_or_email = bool(
        re.search(r'https?://|www\.|\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', processed)
    )

    alpha_tokens = [token for token in tokens if re.fullmatch(r"[a-z']+", token)]
    if len(alpha_tokens) < 2 and not has_url_or_email:
        return True

    known_semantic_terms = {
        'account', 'bank', 'security', 'alert', 'otp', 'password', 'login', 'verify',
        'statement', 'order', 'delivery', 'invoice', 'payment', 'support', 'team',
        'official', 'website', 'review', 'activity', 'customer', 'card', 'transaction'
    }
    semantic_hits = len(set(tokens).intersection(known_semantic_terms))

    long_alpha = [token for token in alpha_tokens if len(token) >= 4]
    vowel_poor = [token for token in long_alpha if not re.search(r'[aeiou]', token)]
    vowel_poor_ratio = (len(vowel_poor) / len(long_alpha)) if long_alpha else 0.0

    unique_ratio = (len(set(tokens)) / len(tokens)) if tokens else 0.0

    if not has_url_or_email and semantic_hits == 0 and vowel_poor_ratio >= 0.6:
        return True

    if not has_url_or_email and semantic_hits == 0 and unique_ratio <= 0.45:
        return True

    return False

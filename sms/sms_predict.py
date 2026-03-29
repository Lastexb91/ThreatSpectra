import re
from urllib.parse import urlparse

from models.load_models import sms_model, sms_tfidf
from utils.text_utils import is_low_information_text
from url.url_predict import build_prediction_response


def _extract_sms_urls(text):
    raw_urls = re.findall(r'https?://[^\s<>")\]]+', str(text or ''))
    return [url.rstrip('.,;:!?)') for url in raw_urls]


def _is_trusted_sms_domain(domain):
    trusted_domains = {
        'amazon.com', 'amazon.in', 'amazon.co.uk',
        'ups.com', 'fedex.com', 'usps.com', 'dhl.com',
        'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citi.com',
        'hsbc.com', 'americanexpress.com', 'discover.com', 'capitalone.com',
        'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com',
        'pnbindia.in', 'canarabank.com', 'onlinesbi.sbi'
    }
    d = str(domain or '').lower().strip()
    return d in trusted_domains or any(d.endswith('.' + trusted) for trusted in trusted_domains)


def _contains_phishing_sms_url(urls):
    for raw_url in urls:
        try:
            host = urlparse(raw_url).netloc.lower().split(':')[0].strip()
            if _is_trusted_sms_domain(host):
                continue
            url_result = build_prediction_response(raw_url)
            if url_result.get('result') == 'Phishing':
                return True
        except Exception:
            # Keep SMS decision flow running even if one URL lookup fails.
            continue
    return False


def _is_gibberish_sms(text):
    normalized = str(text or '').lower().strip()
    if not normalized:
        return True

    tokens = re.findall(r"[a-z0-9']+", normalized)
    if not tokens:
        return True

    has_url = bool(re.search(r'https?://|www\.', normalized))

    conversational_tokens = {
        'ok', 'okay', 'thanks', 'thank', 'hi', 'hello', 'yes', 'no',
        'call', 'me', 'please', 'pls', 'text', 'msg', 'tomorrow', 'today',
        'later', 'meet', 'meeting', 'reach', 'urgent'
    }
    semantic_tokens = {
        'account', 'bank', 'security', 'verify', 'login', 'otp', 'password',
        'delivery', 'package', 'invoice', 'payment', 'support', 'transaction'
    }
    common_language_tokens = {
        'the', 'a', 'an', 'and', 'or', 'to', 'for', 'from', 'with', 'of', 'on',
        'is', 'are', 'was', 'were', 'be', 'this', 'that', 'your', 'you', 'we',
        'our', 'in', 'at', 'by', 'as', 'it', 'please', 'dear', 'hello', 'hi',
        'thanks', 'thank', 'team', 'today', 'tomorrow', 'now', 'update', 'service'
    }
    likely_legit_short_tokens = {
        'pls', 'plz', 'msg', 'txt', 'ok', 'thx', 'u', 'ur', 'r', 'pm', 'am',
        'meet', 'meeting', 'call', 'later', 'time', 'soon', 'reach', 'done'
    }

    known_hits = len(set(tokens).intersection(conversational_tokens.union(semantic_tokens)))
    mixed_alnum_tokens = [
        token for token in tokens
        if re.search(r'[a-z]', token) and re.search(r'\d', token)
    ]
    mixed_ratio = (len(mixed_alnum_tokens) / len(tokens)) if tokens else 0.0
    digit_rich_tokens = [token for token in tokens if re.search(r'\d', token)]
    digit_ratio = (len(digit_rich_tokens) / len(tokens)) if tokens else 0.0
    semantic_density = (known_hits / len(set(tokens))) if tokens else 0.0
    common_language_hits = len(set(tokens).intersection(common_language_tokens))
    known_vocab = conversational_tokens.union(semantic_tokens).union(common_language_tokens).union(likely_legit_short_tokens)

    alpha_tokens = [token for token in tokens if re.fullmatch(r"[a-z']+", token)]
    long_alpha = [token for token in alpha_tokens if len(token) >= 4]
    vowel_poor = [token for token in long_alpha if not re.search(r'[aeiou]', token)]
    vowel_poor_ratio = (len(vowel_poor) / len(long_alpha)) if long_alpha else 0.0
    avg_token_length = (sum(len(token) for token in alpha_tokens) / len(alpha_tokens)) if alpha_tokens else 0.0
    unknown_alpha_tokens = [token for token in alpha_tokens if token not in known_vocab]
    unknown_ratio = (len(unknown_alpha_tokens) / len(alpha_tokens)) if alpha_tokens else 0.0

    if not has_url and len(tokens) <= 4 and known_hits == 0:
        return True

    if not has_url and known_hits == 0 and vowel_poor_ratio >= 0.6:
        return True

    # Catch random alphanumeric-noise messages with very weak natural-language context.
    if not has_url and len(tokens) >= 5 and mixed_ratio >= 0.35 and known_hits <= 1:
        return True

    # Catch digit-heavy noisy blocks (often repeated) that include a few filler words.
    if not has_url and len(tokens) >= 8 and digit_ratio >= 0.30 and semantic_density <= 0.35:
        return True

    # Catch long alphabetic gibberish blocks with no meaningful language anchors.
    if (
        not has_url
        and len(tokens) >= 10
        and len(alpha_tokens) >= 8
        and known_hits <= 1
        and common_language_hits <= 1
        and avg_token_length >= 4.2
    ):
        return True

    # Catch semi-readable gibberish clusters that are mostly unknown words.
    if (
        not has_url
        and len(alpha_tokens) >= 6
        and unknown_ratio >= 0.72
        and vowel_poor_ratio >= 0.45
        and common_language_hits <= 2
    ):
        return True

    # Catch long unknown-word blocks even if a few vowels exist.
    if (
        not has_url
        and len(alpha_tokens) >= 10
        and unknown_ratio >= 0.78
        and avg_token_length >= 4.0
        and common_language_hits <= 2
    ):
        return True

    return False


def _looks_like_obfuscated_phishing_sms(text):
    normalized = str(text or '').lower().strip()
    if not normalized:
        return False

    tokens = re.findall(r"[a-z0-9']+", normalized)
    if len(tokens) < 4:
        return False

    abbr_map = {
        'accnt': 'account',
        'acct': 'account',
        'vrfy': 'verify',
        'rqst': 'request',
        'snd': 'send',
        'detls': 'details',
        'cnfrm': 'confirm',
        'plz': 'please',
        'upd8': 'update',
        'ur': 'your',
        'rmv': 'remove',
        'restrctn': 'restriction',
        'info': 'information',
    }

    normalized_tokens = [abbr_map.get(token, token) for token in tokens]
    text_norm = ' '.join(normalized_tokens)

    suspicious_abbrev_tokens = {
        'accnt', 'acct', 'vrfy', 'rqst', 'snd', 'detls', 'cnfrm', 'upd8', 'restrctn', 'rmv'
    }
    abbrev_hits = sum(1 for token in tokens if token in suspicious_abbrev_tokens)

    risk_terms = {
        'account', 'verify', 'request', 'send', 'details', 'confirm', 'update',
        'information', 'restriction', 'suspend', 'suspension', 'login', 'otp',
        'password', 'pin', 'cvv', 'urgent', 'asap'
    }
    risk_hits = len(set(normalized_tokens).intersection(risk_terms))

    account_flow = bool(re.search(r'(account).{0,25}(verify|update|request|restriction|suspend|suspension)', text_norm))
    credential_flow = bool(re.search(r'(send|confirm|provide|share).{0,25}(otp|password|pin|cvv|details|information|credential)', text_norm))
    pressure_flow = bool(re.search(r'(verify|update|confirm).{0,25}(account|details|information|identity)', text_norm))

    if account_flow and (credential_flow or pressure_flow):
        return True

    if abbrev_hits >= 3 and risk_hits >= 4:
        return True

    return False


def sms_post_decision_overlay(sms_text, base_prediction):
    text = str(sms_text or '').lower()
    words = set(re.findall(r"[a-z0-9']+", text))
    url_domains = {
        domain.lower().strip('.,;:!?)(')
        for domain in re.findall(r'https?://([^\s/]+)', text)
        if domain
    }

    trusted_domains = {
        'amazon.com', 'amazon.in', 'amazon.co.uk',
        'ups.com', 'fedex.com', 'usps.com', 'dhl.com',
        'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citi.com',
        'hsbc.com', 'americanexpress.com', 'discover.com', 'capitalone.com',
        'hdfcbank.com', 'icicibank.com', 'axisbank.com', 'kotak.com',
        'pnbindia.in', 'canarabank.com', 'onlinesbi.sbi'
    }
    transactional_terms = {
        'order', 'shipped', 'shipping', 'delivery', 'arrive', 'arriving',
        'track', 'tracking', 'package', 'thank', 'shopping', 'expected',
        'flight', 'boarding', 'gate', 'service', 'request', 'resolved',
        'support', 'appointment', 'confirmed', 'statement', 'monthly', 'portal'
    }
    logistics_terms = {
        'courier', 'shipment', 'transit', 'track', 'tracking', 'delivery', 'package',
        'shipped', 'arrive', 'arriving'
    }
    strong_attack_terms = {
        'urgent', 'verify', 'verification', 'password', 'otp',
        'pin', 'cvv', 'suspended', 'limited', 'reset', 'login',
        'gift', 'reward', 'winner',
        'claim', 'prize', 'wallet'
    }
    mild_attack_terms = {'secure', 'confirm', 'identity', 'alert', 'account', 'bank'}
    credential_attack_terms = {
        'verify', 'verification', 'password', 'otp', 'pin', 'cvv',
        'login', 'reset', 'claim', 'prize', 'reward', 'winner',
        'wallet', 'suspended', 'limited', 'urgent'
    }
    hard_credential_attack_terms = {
        'verify', 'verification', 'password', 'otp', 'pin', 'cvv', 'login', 'reset'
    }
    safe_context_terms = {
        'statement', 'monthly', 'portal', 'boarding', 'gate',
        'request', 'resolved', 'support', 'appointment', 'confirmed',
        'ready', 'view', 'official', 'app', 'securely', 'available'
    }
    security_alert_terms = {
        'unusual', 'attempt', 'detected', 'temporarily', 'blocked',
        'device', 'secure', 'official', 'helpline', 'contact',
        'review', 'activity', 'unblock', 'customer', 'care'
    }
    bank_transaction_terms = {
        'debited', 'credited', 'account', 'ending', 'transaction',
        'initiated', 'helpline', 'official', 'processed', 'transfer', 'neft',
        'successful', 'successfully', 'fixed', 'deposit', 'opened'
    }
    payroll_safe_terms = {
        'payroll', 'reimbursement', 'approved', 'reflect', 'salary',
        'payslip', 'finance', 'expense', 'claim'
    }
    insurance_safe_terms = {
        'insurance', 'claim', 'request', 'approved', 'credited',
        'shortly', 'policy', 'documents', 'received', 'review'
    }
    it_ops_terms = {
        'it', 'service', 'password', 'reset', 'mfa', 'mailbox', 'corporate', 'account'
    }
    completion_terms = {'completed', 'successfully', 'enabled', 'changed', 'done'}
    bank_identity_tokens = {
        'sbi', 'hdfc', 'icici', 'axis', 'kotak', 'yesbank',
        'pnb', 'canara'
    }
    bank_identity_phrases = {
        'state bank of india', 'sbi bank',
        'hdfc bank',
        'icici bank',
        'axis bank',
        'kotak mahindra bank', 'kotak bank',
        'punjab national bank', 'pnb bank',
        'canara bank'
    }

    transactional_hits = len(words.intersection(transactional_terms))
    logistics_hits = len(words.intersection(logistics_terms))
    strong_attack_hits = len(words.intersection(strong_attack_terms))
    mild_attack_hits = len(words.intersection(mild_attack_terms))
    credential_attack_hits = len(words.intersection(credential_attack_terms))
    hard_credential_attack_hits = len(words.intersection(hard_credential_attack_terms))
    safe_context_hits = len(words.intersection(safe_context_terms))
    security_alert_hits = len(words.intersection(security_alert_terms))
    bank_transaction_hits = len(words.intersection(bank_transaction_terms))
    payroll_safe_hits = len(words.intersection(payroll_safe_terms))
    insurance_safe_hits = len(words.intersection(insurance_safe_terms))
    it_ops_hits = len(words.intersection(it_ops_terms))
    completion_hits = len(words.intersection(completion_terms))
    bank_identity_hits = len(words.intersection(bank_identity_tokens))
    bank_identity_hits += sum(1 for phrase in bank_identity_phrases if phrase in text)
    trusted_domain_hits = sum(
        1 for domain in url_domains
        if domain in trusted_domains or any(domain.endswith('.' + root) for root in trusted_domains)
    )
    suspicious_link_keywords = {'secure', 'login', 'verify', 'update', 'access', 'account', 'kyc', 'signin'}
    untrusted_bank_lookalike_link = any(
        not (domain in trusted_domains or any(domain.endswith('.' + root) for root in trusted_domains))
        and (
            any(token in domain for token in bank_identity_tokens)
            or any(keyword in domain for keyword in suspicious_link_keywords)
        )
        for domain in url_domains
    )
    has_protective_warning = 'do not share' in text and ('otp' in words or 'password' in words)
    device_alert_context = (
        'new device' in text or 'if this was not you' in text or 'unauthorized' in text
    )
    suspicious_activity_context = (
        'if not you' in text
        or "if this wasn't you" in text
        or 'unusual login attempt' in text
        or 'incorrect pin attempts' in text
        or 'temporarily blocked' in text
        or 'official helpline' in text
        or 'customer care' in text
        or 'review activity' in text
    )
    protective_warning_pattern = re.search(r"(do\s*not|don't|never)\s+share", text)
    has_protective_warning = bool(
        protective_warning_pattern
        and (
            'otp' in words
            or 'password' in words
            or 'pin' in words
            or 'cvv' in words
            or 'credential' in words
            or 'credentials' in words
            or 'login credentials' in text
        )
    )
    asks_for_sensitive_details = bool(
        re.search(r'(enter|submit|provide|confirm).{0,30}(otp|password|cvv|pin|credential|credentials)', text)
        or (
            re.search(r'share.{0,30}(otp|password|cvv|pin|credential|credentials|login)', text)
            and not has_protective_warning
        )
    )
    asks_to_send_sensitive_details = bool(
        re.search(r'(send|reply).{0,30}(otp|password|cvv|pin|credential|credentials|login)', text)
        and not has_protective_warning
    )

    if base_prediction == 'Phishing':
        if (
            trusted_domain_hits >= 1
            and not asks_for_sensitive_details
            and not untrusted_bank_lookalike_link
            and (
                has_protective_warning
                or safe_context_hits >= 2
                or ('official website' in text and ('review' in words or 'activity' in words or 'statement' in words))
            )
        ):
            return 'Safe'

        if trusted_domain_hits >= 1 and transactional_hits >= 3 and strong_attack_hits == 0 and mild_attack_hits <= 1:
            return 'Safe'

        # Allow trusted-domain courier tracking updates when no attack cues exist.
        if (
            trusted_domain_hits >= 1
            and logistics_hits >= 2
            and strong_attack_hits == 0
            and not asks_for_sensitive_details
        ):
            return 'Safe'

        if not url_domains and transactional_hits >= 2 and strong_attack_hits == 0:
            return 'Safe'

        if trusted_domain_hits >= 1 and safe_context_hits >= 2 and strong_attack_hits == 0:
            return 'Safe'

        if (
            trusted_domain_hits >= 1
            and bank_identity_hits >= 1
            and security_alert_hits >= 2
            and suspicious_activity_context
            and not asks_for_sensitive_details
            and (hard_credential_attack_hits <= 1 or has_protective_warning)
        ):
            return 'Safe'

        if (
            trusted_domain_hits >= 1
            and bank_identity_hits >= 1
            and has_protective_warning
            and device_alert_context
            and not asks_for_sensitive_details
        ):
            return 'Safe'

        if (
            trusted_domain_hits >= 1
            and 'statement' in words
            and 'monthly' in words
            and credential_attack_hits == 0
        ):
            return 'Safe'

        if (
            not url_domains
            and bank_identity_hits >= 1
            and bank_transaction_hits >= 3
            and hard_credential_attack_hits == 0
        ):
            return 'Safe'

        if (
            not url_domains
            and bank_identity_hits >= 1
            and security_alert_hits >= 2
            and suspicious_activity_context
            and not asks_for_sensitive_details
            and (hard_credential_attack_hits <= 1 or has_protective_warning)
        ):
            return 'Safe'

        if (
            not url_domains
            and payroll_safe_hits >= 3
            and hard_credential_attack_hits == 0
        ):
            return 'Safe'

        if (
            not url_domains
            and insurance_safe_hits >= 4
            and hard_credential_attack_hits == 0
        ):
            return 'Safe'

        if (
            not url_domains
            and it_ops_hits >= 3
            and completion_hits >= 1
            and 'verify' not in words
            and 'otp' not in words
            and 'cvv' not in words
            and 'pin' not in words
        ):
            return 'Safe'

    if base_prediction == 'Safe':
        if asks_to_send_sensitive_details:
            return 'Phishing'

        # Escalate reward-transfer scams that pressure PIN/CVV confirmation.
        if (
            ('pin' in words or 'cvv' in words)
            and ('urgent' in words or 'confirm' in words or 'immediately' in words)
            and ('prize' in words or 'reward' in words or 'transfer' in words or 'claim' in words)
            and not has_protective_warning
        ):
            return 'Phishing'

        if untrusted_bank_lookalike_link and (bank_identity_hits >= 1 or 'bank' in words):
            return 'Phishing'

        legitimate_security_advisory = (
            has_protective_warning
            and (trusted_domain_hits >= 1 or bank_identity_hits >= 1)
            and not asks_for_sensitive_details
        )
        if (
            strong_attack_hits >= 3
            and ('otp' in words or 'password' in words or 'verify' in words)
            and not legitimate_security_advisory
        ):
            return 'Phishing'

    return base_prediction


def predict_sms_with_tfidf(sms_text):
    normalized_text = str(sms_text or '').strip()
    if (
        is_low_information_text(normalized_text)
        or _is_gibberish_sms(normalized_text)
        or _looks_like_obfuscated_phishing_sms(normalized_text)
    ):
        return {
            'prediction': 'Phishing',
            'confidence': 0.99,
        }

    urls = _extract_sms_urls(normalized_text)
    if urls and _contains_phishing_sms_url(urls):
        return {
            'prediction': 'Phishing',
            'confidence': 0.99,
        }

    x_input = sms_tfidf.transform([normalized_text])
    prediction = sms_model.predict(x_input)[0]

    prediction_text = str(prediction).strip().lower()
    phishing_aliases = {'1', 'spam', 'phishing', 'smishing', 'fraud', 'scam', 'unsafe', 'malicious'}
    safe_aliases = {'0', 'ham', 'safe', 'legitimate', 'benign', 'normal'}

    if prediction_text in phishing_aliases:
        label = 'Phishing'
    elif prediction_text in safe_aliases:
        label = 'Safe'
    else:
        try:
            label = 'Phishing' if int(float(prediction_text)) == 1 else 'Safe'
        except Exception:
            label = 'Phishing'

    confidence = None
    if hasattr(sms_model, 'predict_proba'):
        probabilities = sms_model.predict_proba(x_input)[0]
        confidence = float(max(probabilities))

    label = sms_post_decision_overlay(normalized_text, label)

    return {
        'prediction': label,
        'confidence': confidence,
    }

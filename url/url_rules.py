from urllib.parse import urlparse

from models.load_models import HIGH_RISK_MIN_SIGNALS, model, model_feature_names
from url.url_features import is_private_or_local_host, looks_like_brand_typo


def high_risk_overlay(url, extracted_features):
    parsed = urlparse(url)
    domain_name = parsed.netloc.split(':')[0].lower()
    path_query = f'{parsed.path}?{parsed.query}'.lower()

    leet_map = str.maketrans({
        '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g'
    })
    normalized_domain = domain_name.translate(leet_map)
    raw_labels = [label for label in domain_name.split('.') if label]
    is_local_or_private = is_private_or_local_host(domain_name)

    brand_keywords = (
        'bank', 'paypal', 'microsoft', 'google', 'apple', 'amazon',
        'facebook', 'instagram', 'netflix', 'crypto', 'wallet'
    )
    major_brand_roots = (
        'google', 'paypal', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram',
        'netflix', 'github', 'binance', 'coinbase', 'whatsapp'
    )
    action_keywords = ('login', 'verify', 'secure', 'update', 'reset', 'signin')
    security_words = ('security', 'secure', 'verify', 'account', 'auth', 'support')

    suspicious_domain_pattern = (
        ('-' in domain_name and any(k in domain_name for k in brand_keywords))
        or any(k in domain_name for k in ('free', 'bonus', 'gift', 'claim', 'support-security'))
        or (any(k in domain_name for k in brand_keywords) and any(k in path_query for k in action_keywords))
    )

    typosquatted_brand = any(root in normalized_domain for root in major_brand_roots) and not any(
        normalized_domain.endswith(f'{root}.com') or normalized_domain == root for root in major_brand_roots
    )
    brand_typo_variant = looks_like_brand_typo(normalized_domain, major_brand_roots)
    hostname_without_tld = '-'.join(raw_labels[:-1]) if len(raw_labels) > 1 else raw_labels[0]
    suspicious_security_subdomain = any(word in hostname_without_tld for word in security_words)
    brand_plus_security_combo = typosquatted_brand and (
        suspicious_security_subdomain or any(k in path_query for k in action_keywords)
    )
    shortener_action_combo = (extracted_features[2] == -1) and any(k in path_query for k in action_keywords)

    signals = {
        'ip_in_url': extracted_features[0] == -1,
        'url_shortener': extracted_features[2] == -1,
        'at_symbol': extracted_features[3] == -1,
        'non_resolving_domain': extracted_features[24] == -1,
        'local_or_private_host': is_local_or_private,
        'suspicious_domain_pattern': suspicious_domain_pattern,
        'typosquatted_brand': typosquatted_brand,
        'brand_typo_variant': brand_typo_variant,
        'suspicious_security_subdomain': suspicious_security_subdomain,
        'brand_plus_security_combo': brand_plus_security_combo,
        'shortener_action_combo': shortener_action_combo,
    }
    active = [name for name, active_flag in signals.items() if active_flag]
    non_resolving_hard_trigger = 'non_resolving_domain' in active
    brand_combo_hard_trigger = 'brand_plus_security_combo' in active
    brand_typo_hard_trigger = 'brand_typo_variant' in active
    local_host_hard_trigger = 'local_or_private_host' in active
    shortener_hard_trigger = ('shortener_action_combo' in active) or ('url_shortener' in active)
    triggered = (
        non_resolving_hard_trigger
        or brand_combo_hard_trigger
        or brand_typo_hard_trigger
        or local_host_hard_trigger
        or shortener_hard_trigger
        or (len(active) >= HIGH_RISK_MIN_SIGNALS)
    )

    return {
        'triggered': triggered,
        'hard_trigger_non_resolving_domain': non_resolving_hard_trigger,
        'hard_trigger_brand_plus_security_combo': brand_combo_hard_trigger,
        'hard_trigger_brand_typo_variant': brand_typo_hard_trigger,
        'hard_trigger_local_or_private_host': local_host_hard_trigger,
        'hard_trigger_shortener_action_combo': shortener_hard_trigger,
        'active_signals': active,
        'signal_count': len(active),
    }


def build_feature_diagnostics(extracted_features):
    diagnostics = []
    if not model_feature_names or len(model_feature_names) != len(extracted_features):
        return diagnostics

    if hasattr(model, 'feature_importances_'):
        importances = list(model.feature_importances_)
    else:
        importances = [0.0] * len(extracted_features)

    for idx, (name, value) in enumerate(zip(model_feature_names, extracted_features)):
        importance = float(importances[idx]) if idx < len(importances) else 0.0
        if value == -1:
            risk_direction = 'high_risk'
            risk_contribution = round(importance, 6)
        elif value == 0:
            risk_direction = 'neutral_or_unknown'
            risk_contribution = round(importance * 0.5, 6)
        else:
            risk_direction = 'safe_leaning'
            risk_contribution = round(-importance * 0.25, 6)

        diagnostics.append({
            'feature': name,
            'value': int(value),
            'importance': round(importance, 6),
            'risk_direction': risk_direction,
            'risk_contribution': risk_contribution,
        })

    diagnostics.sort(key=lambda item: abs(item['risk_contribution']), reverse=True)
    return diagnostics


def compute_risk_level(result, phishing_probability, overlay):
    if overlay.get('triggered') and (
        overlay.get('hard_trigger_non_resolving_domain')
        or overlay.get('hard_trigger_brand_plus_security_combo')
        or overlay.get('hard_trigger_local_or_private_host')
        or overlay.get('hard_trigger_shortener_action_combo')
    ):
        return 'Critical'

    if result == 'Phishing':
        if phishing_probability >= 0.7:
            return 'High'
        return 'Medium'

    if phishing_probability >= 0.45:
        return 'Medium'
    return 'Low'


def build_reason_summary(result, overlay, top_risky_features, safe_probability, phishing_probability):
    signal_labels = {
        'ip_in_url': 'The URL uses an IP address instead of a normal domain name.',
        'url_shortener': 'The URL uses a link shortener service.',
        'at_symbol': 'The URL contains an @ symbol, which is a known phishing trick.',
        'non_resolving_domain': 'The domain does not resolve in DNS (likely invalid or suspicious).',
        'local_or_private_host': 'The URL points to a local/private host, not a public website.',
        'suspicious_domain_pattern': 'The domain pattern looks suspicious (brand/security keyword mix).',
        'typosquatted_brand': 'The domain appears to mimic a known brand (possible typosquatting).',
        'brand_typo_variant': 'The domain name looks like a typo variant of a known brand.',
        'suspicious_security_subdomain': 'The hostname uses security/account keywords often used in phishing.',
        'brand_plus_security_combo': 'Brand-like domain combined with security/login wording is high risk.',
        'shortener_action_combo': 'Shortened link combined with login/verify wording is high risk.',
    }

    feature_labels = {
        'HTTPS': 'HTTPS usage',
        'PrefixSuffix-': 'Hyphenated domain pattern',
        'AnchorURL': 'Anchor link behavior',
        'WebsiteTraffic': 'Website traffic signal',
        'LinksPointingToPage': 'Backlink signal',
        'GoogleIndex': 'Search index signal',
        'RequestURL': 'External resource loading pattern',
        'SubDomains': 'Subdomain structure',
        'LinksInScriptTags': 'External script/link pattern',
        'DNSRecording': 'DNS record presence',
        'UsingIP': 'IP usage in URL',
    }

    reasons = []
    active_signals = overlay.get('active_signals', [])
    for signal in active_signals:
        if signal in signal_labels:
            reasons.append(signal_labels[signal])

    for item in top_risky_features[:4]:
        fname = item.get('feature')
        contribution = item.get('risk_contribution', 0)
        value = item.get('value')
        if contribution <= 0:
            continue
        label = feature_labels.get(fname, fname)
        if value == -1:
            reasons.append(f'{label} indicates a high-risk pattern.')
        elif value == 0:
            reasons.append(f'{label} is uncertain/neutral, which increases risk.')

    if result == 'Safe':
        if safe_probability >= 0.85:
            reasons.insert(0, 'Most evaluated signals align with legitimate website behavior.')
        else:
            reasons.insert(0, 'The URL appears safe, but some weak risk indicators were found.')
    else:
        reasons.insert(0, f'Phishing probability is elevated at {round(phishing_probability * 100, 1)}%.')

    deduped = []
    seen = set()
    for reason in reasons:
        if reason not in seen:
            deduped.append(reason)
            seen.add(reason)
    return deduped[:8]

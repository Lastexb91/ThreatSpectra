import re

import pandas as pd

from email_features import extract_email_features
from email_rules import (
    contains_phishing_url,
    detect_malicious_intent,
    extract_email_domains,
    extract_email_urls,
    is_trusted_domain,
)
from models.load_models import EMAIL_FEATURE_COLUMNS, email_model
from utils.text_utils import is_low_information_text, preprocess_email_text


def email_post_decision_overlay(email_text, features, base_prediction, return_reason=False):
    def _decision(label, reason):
        if return_reason:
            return label, reason
        return label

    text = preprocess_email_text(email_text)
    words = set(re.findall(r"[a-z0-9']+", text))
    url_domains = {
        domain.lower().strip('.,;:!?)(')
        for domain in re.findall(r'https?://([^\s/]+)', text)
        if domain
    }

    high_risk_terms = {
        'suspended', 'limited', 'verify', 'password', 'login', 'confirm',
        'unauthorized', 'reset', 'kyc', 'wallet', 'otp', 'pin',
        'deactivation', 'expired', 'invoice', 'payment', 'bank',
        'beneficiary', 'wire', 'claim', 'reward', 'gift', 'compromised',
        'pay', 'refund', 'card', 'cvv', 'prize', 'winner', 'billing',
        'suspension', 'hold', 'release', 'renew'
    }
    benign_terms = {
        'meeting', 'agenda', 'report', 'review', 'invoice', 'receipt',
        'onboarding', 'maintenance', 'project', 'ticket', 'newsletter',
        'notes', 'approve', 'application', 'holiday', 'presentation',
        'contract', 'training', 'dataset', 'calendar', 'invite', 'team'
    }
    safe_context_terms = {
        'statement', 'monthly', 'official', 'support', 'contact', 'thank',
        'regards', 'available', 'securely', 'banking'
    }
    professional_notice_terms = {
        'interview', 'schedule', 'scheduled', 'confirmation', 'confirm',
        'position', 'developer', 'hr', 'team', 'meeting', 'reschedule',
        'reply', 'speaking', 'regards', 'solutions'
    }
    scheduling_markers = {
        'date', 'time', 'mode', 'online', 'available', 'minutes', 'prior'
    }
    business_update_terms = {
        'project', 'update', 'weekly', 'summary', 'progress', 'milestone',
        'walkthrough', 'feedback', 'backend', 'frontend', 'api', 'apis',
        'authentication', 'design', 'bugs', 'testing', 'cycle', 'manager',
        'developer', 'position', 'interview', 'schedule', 'team'
    }
    strong_attack_terms = {
        'password', 'otp', 'pin', 'cvv', 'wallet', 'gift', 'reward', 'claim',
        'winner', 'suspended', 'limited', 'unauthorized', 'reset', 'verify'
    }
    trusted_domains = {
        'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'citi.com',
        'hsbc.com', 'americanexpress.com', 'discover.com', 'capitalone.com',
        'paypal.com', 'microsoft.com', 'google.com', 'apple.com', 'amazon.com'
    }

    high_risk_hits = len(words.intersection(high_risk_terms))
    benign_hits = len(words.intersection(benign_terms))
    safe_context_hits = len(words.intersection(safe_context_terms))
    professional_notice_hits = len(words.intersection(professional_notice_terms))
    scheduling_hits = len(words.intersection(scheduling_markers))
    business_update_hits = len(words.intersection(business_update_terms))
    strong_attack_hits = len(words.intersection(strong_attack_terms))
    trusted_domain_hits = sum(
        1 for domain in url_domains
        if domain in trusted_domains or any(domain.endswith('.' + root) for root in trusted_domains)
    )

    num_links = int(features.get('num_links', 0) or 0)
    num_email_addresses = int(features.get('num_email_addresses', 0) or 0)
    num_urgent_keywords = int(features.get('num_urgent_keywords', 0) or 0)
    protective_warning_pattern = re.search(r"(do\s*not|don't|never)\s+share", text)
    has_protective_warning = bool(
        protective_warning_pattern
        and (
            'password' in words
            or 'otp' in words
            or 'pin' in words
            or 'cvv' in words
            or 'credential' in words
            or 'credentials' in words
        )
    )
    no_immediate_action_notice = (
        'does not require any immediate action' in text
        or 'no immediate action' in text
        or 'for informational purposes' in text
    )
    asks_for_sensitive_details = bool(
        re.search(r'(enter|submit|provide|confirm).{0,30}(otp|password|cvv|pin|credential|credentials)', text)
        or (
            re.search(r'share.{0,30}(otp|password|cvv|pin|credential|credentials)', text)
            and not has_protective_warning
        )
    )
    legitimate_protective_advisory = (
        num_links == 0
        and num_email_addresses == 0
        and has_protective_warning
        and no_immediate_action_notice
        and not asks_for_sensitive_details
    )
    legitimate_professional_notice = (
        num_links == 0
        and not asks_for_sensitive_details
        and strong_attack_hits == 0
        and (
            'interview' in words
            or (
                professional_notice_hits >= 3
                and scheduling_hits >= 1
                and ('hr' in words or 'team' in words)
            )
        )
    )
    legitimate_business_update = (
        num_links <= 1
        and not asks_for_sensitive_details
        and strong_attack_hits == 0
        and (
            business_update_hits >= 4
            or (
                ('project' in words or 'update' in words or 'summary' in words)
                and business_update_hits >= 3
            )
        )
    )

    if base_prediction == 'Safe':
        if legitimate_business_update:
            return _decision('Safe', 'safe_legitimate_business_update')
        if legitimate_professional_notice:
            return _decision('Safe', 'safe_legitimate_professional_notice')
        if legitimate_protective_advisory and safe_context_hits >= 1:
            return _decision('Safe', 'safe_legitimate_protective_advisory')
        if high_risk_hits >= 2:
            return _decision('Phishing', 'escalate_high_risk_terms')
        if (num_urgent_keywords >= 1 and high_risk_hits >= 1) or (num_links >= 1 and high_risk_hits >= 1):
            return _decision('Phishing', 'escalate_urgent_or_link_plus_risk')
        if num_links >= 1 and ('login' in words or 'verify' in words or 'password' in words):
            return _decision('Phishing', 'escalate_link_with_credential_terms')
        if num_email_addresses >= 1 and high_risk_hits >= 2:
            return _decision('Phishing', 'escalate_embedded_email_plus_risk')

    if base_prediction == 'Phishing':
        no_attack_surface = num_links == 0 and num_email_addresses == 0
        if legitimate_business_update:
            return _decision('Safe', 'downgrade_legitimate_business_update')
        if legitimate_professional_notice:
            return _decision('Safe', 'downgrade_legitimate_professional_notice')
        if legitimate_protective_advisory and safe_context_hits >= 1:
            return _decision('Safe', 'downgrade_legitimate_protective_advisory')
        if no_attack_surface and benign_hits >= 2 and high_risk_hits == 0:
            return _decision('Safe', 'downgrade_no_attack_surface_benign_context')

        if (
            no_attack_surface
            and 'statement' in words
            and 'monthly' in words
            and ('official' in words or 'support' in words or 'regards' in words)
            and strong_attack_hits == 0
            and not asks_for_sensitive_details
        ):
            return _decision('Safe', 'downgrade_monthly_statement_notice')

        if (
            trusted_domain_hits >= 1
            and num_links <= 1
            and safe_context_hits >= 2
            and strong_attack_hits == 0
        ):
            return _decision('Safe', 'downgrade_trusted_domain_statement_notice')

    return _decision(base_prediction, 'model_prediction')


def predict_email_with_features(email_text):
    if len(email_text.strip()) < 10:
        return {
            'prediction': 'Phishing',
            'confidence': 0.99,
            'features': extract_email_features(email_text),
            'risk_level': 'High',
            'final_decision_reason': 'Input is too short to establish legitimacy and is treated as phishing-risk.',
            'supporting_signals': [
                'Very short input has insufficient context.',
            ],
            'reasons': [
                'Very short input has insufficient context and is treated as risky.',
            ],
            'detected_signals': {
                'links': 0,
                'urgent_keywords': 0,
                'sensitive_request': False,
                'intent': 'Suspicious',
            },
        }

    if is_low_information_text(email_text):
        return {
            'prediction': 'Phishing',
            'confidence': 0.99,
            'features': extract_email_features(email_text),
            'risk_level': 'High',
            'final_decision_reason': 'Low-information/gibberish pattern detected, so the text is treated as phishing-risk.',
            'supporting_signals': [
                'Input appears low-information or gibberish.',
            ],
            'reasons': [
                'Input appears low-information or gibberish and cannot be trusted as safe.',
            ],
            'detected_signals': {
                'links': 0,
                'urgent_keywords': 0,
                'sensitive_request': False,
                'intent': 'Suspicious',
            },
        }

    feature_values = extract_email_features(email_text)

    row = {col: feature_values.get(col, 0) for col in EMAIL_FEATURE_COLUMNS}
    model_input = pd.DataFrame([row], columns=EMAIL_FEATURE_COLUMNS)

    proba = email_model.predict_proba(model_input)[0]
    classes = list(email_model.classes_)

    safe_prob = 0.0
    phish_prob = 0.0
    if 1 in classes:
        safe_prob = float(proba[classes.index(1)])
    if 0 in classes:
        phish_prob = float(proba[classes.index(0)])

    print('SAFE PROB:', safe_prob, 'PHISH PROB:', phish_prob)

    text_lower = email_text.lower()
    tokens = set(re.findall(r"[a-z0-9']+", text_lower))
    token_list = re.findall(r"[a-z0-9']+", text_lower)
    semantic_context_terms = {
        'meeting', 'project', 'summary', 'report', 'schedule', 'interview', 'team',
        'milestone', 'walkthrough', 'feedback', 'invoice', 'receipt', 'presentation',
        'account', 'security', 'support', 'statement', 'notice', 'update', 'service',
        'customer', 'transaction', 'delivery', 'order', 'confirm', 'verification'
    }
    semantic_hits = len(tokens.intersection(semantic_context_terms))
    digit_heavy_tokens = sum(1 for token in token_list if any(ch.isdigit() for ch in token))
    digit_noise_ratio = (digit_heavy_tokens / len(token_list)) if token_list else 0.0
    reply_info_pattern = bool(re.search(r'(reply|send).{0,25}(info|information|details)', text_lower))
    casual_contact_request = bool(re.search(r'\b(call|text|message|ping|contact|reach)\b', text_lower))
    credential_theft_terms = bool(
        re.search(r'(password|otp|pin|cvv|credential|credentials|verify|verification|login)', text_lower)
    )

    protective_flag = (
        ('do not share' in text_lower or 'never share' in text_lower)
        and ('password' in text_lower or 'otp' in text_lower or 'pin' in text_lower)
    )

    no_action_flag = (
        'no immediate action' in text_lower
        or 'no action is required' in text_lower
        or 'no further action is required' in text_lower
        or 'does not require any immediate action' in text_lower
        or 'does not require any action' in text_lower
        or 'does not require you to provide any information via email' in text_lower
        or 'does not require you to provide any information' in text_lower
        or 'no need to provide any information' in text_lower
        or 'informational' in text_lower
    )
    advisory_context_flag = bool(
        re.search(
            r'(advisory|awareness|reminder|precautionary|security notification|security update|official channels|suspicious activity)',
            text_lower,
        )
    )
    negated_sensitive_instruction = bool(
        re.search(r"(do\s*not|never|don't)\s+(enter|submit|provide|share).{0,30}(otp|password|pin|cvv|credential|credentials)", text_lower)
    )
    sensitive_request_flag = bool(
        re.search(r'(enter|submit|provide|share).{0,30}(otp|password|pin|cvv|credential|credentials)', text_lower)
    )
    unsafe_sensitive_request = sensitive_request_flag and not negated_sensitive_instruction
    no_data_via_email_flag = bool(
        re.search(r"(do\s*not|does\s*not|no\s*need\s*to).{0,40}(provide|share|send|reply).{0,60}(information|details|credentials).{0,20}(email|message)", text_lower)
    )

    print('Protective:', protective_flag, 'NoAction:', no_action_flag)

    urls = extract_email_urls(email_text)
    phishing_url_found = contains_phishing_url(urls) if urls else False
    intent_flag = detect_malicious_intent(email_text)

    forced_prediction = None

    if (
        protective_flag
        and (no_action_flag or no_data_via_email_flag)
        and row['num_links'] == 0
        and not unsafe_sensitive_request
    ):
        forced_prediction = 'Safe'

    if (
        row['num_links'] == 0
        and not phishing_url_found
        and no_action_flag
        and advisory_context_flag
        and not unsafe_sensitive_request
    ):
        forced_prediction = 'Safe'

    if (
        row['num_links'] == 0
        and not intent_flag
        and not protective_flag
        and not no_action_flag
        and not phishing_url_found
        and not re.search(r'(urgent|suspended|suspension|limited|immediately|within \d+)', text_lower)
        and not re.search(r'(password|otp|pin|cvv|credential|credentials|login credentials|account details)', text_lower)
        and bool(re.search(r'(meeting|project|summary|report|schedule|interview|team|milestone|walkthrough|feedback|invoice|receipt|presentation)', text_lower))
    ):
        forced_prediction = 'Safe'

    domains = extract_email_domains(email_text) if urls else []
    trusted = any(is_trusted_domain(domain) for domain in domains)

    if forced_prediction is not None:
        prediction_label = forced_prediction
    else:
        if phishing_url_found:
            prediction_label = 'Phishing'
        elif intent_flag:
            prediction_label = 'Phishing'
        elif trusted and not intent_flag:
            prediction_label = 'Safe'
        elif (
            row['num_links'] == 0
            and row['num_email_addresses'] == 0
            and (digit_noise_ratio >= 0.2 or reply_info_pattern)
            and semantic_hits <= 2
        ):
            prediction_label = 'Phishing'
        elif (
            row['num_links'] == 0
            and row['num_email_addresses'] == 0
            and row['num_urgent_keywords'] == 0
            and not intent_flag
            and semantic_hits >= 2
            and not reply_info_pattern
            and digit_noise_ratio < 0.2
            and bool(re.search(r'(meeting|project|summary|report|schedule|interview|team|milestone|walkthrough|feedback|invoice|receipt|presentation|update|statement|notice)', text_lower))
        ):
            prediction_label = 'Safe'
        elif (
            row['num_links'] == 0
            and row['num_email_addresses'] == 0
            and len(token_list) <= 6
            and casual_contact_request
            and not credential_theft_terms
            and not intent_flag
            and not reply_info_pattern
        ):
            prediction_label = 'Safe'
        elif (
            row['num_links'] == 0
            and row['num_email_addresses'] == 0
            and semantic_hits == 0
            and not advisory_context_flag
            and not protective_flag
            and not no_action_flag
        ):
            prediction_label = 'Phishing'
        elif safe_prob >= 0.50:
            prediction_label = 'Safe'
        else:
            prediction_label = 'Phishing'

    confidence = safe_prob if prediction_label == 'Safe' else phish_prob

    if prediction_label == 'Safe':
        if protective_flag and (no_action_flag or no_data_via_email_flag) and row['num_links'] == 0 and not unsafe_sensitive_request:
            risk_level = 'Low'
        else:
            risk_level = 'Low' if safe_prob >= 0.7 else 'Medium'
    else:
        risk_level = 'High' if phish_prob >= 0.7 else 'Medium'

    supporting_signals = []
    if row['num_links'] == 0:
        supporting_signals.append('No suspicious links detected.')
    else:
        supporting_signals.append(f"Contains {row['num_links']} link(s), which can increase risk.")

    if unsafe_sensitive_request:
        supporting_signals.append('Message appears to request sensitive information.')
    else:
        supporting_signals.append('No direct request for sensitive information detected.')

    if protective_flag and (no_action_flag or no_data_via_email_flag):
        supporting_signals.append('Informational/advisory wording with no required action detected.')
    elif advisory_context_flag:
        supporting_signals.append('Advisory/security-notice context detected.')
    elif intent_flag:
        supporting_signals.append('Urgency or coercive intent indicators were detected.')

    if phishing_url_found:
        supporting_signals.append('At least one linked URL was flagged as phishing.')

    if prediction_label == 'Phishing':
        if phishing_url_found:
            final_decision_reason = 'Phishing URL detected in the message links.'
        elif unsafe_sensitive_request:
            final_decision_reason = 'Sensitive credential request pattern detected.'
        elif row['num_urgent_keywords'] >= 3 and (
            'account' in tokens
            or 'security' in tokens
            or 'verify' in tokens
            or 'login' in tokens
        ):
            final_decision_reason = 'High urgency combined with account-related language.'
            supporting_signals.insert(0, f'High number of urgent keywords detected ({int(row["num_urgent_keywords"])}).')
        elif intent_flag:
            final_decision_reason = 'Urgency/coercion intent pattern detected.'
        else:
            final_decision_reason = 'Multiple phishing-risk patterns outweighed safe indicators.'
    else:
        final_decision_reason = 'No high-risk phishing pattern detected in the message.'

    intent_signal = 'Suspicious' if (intent_flag or prediction_label == 'Phishing') else 'Safe'

    detected_signals = {
        'links': int(row['num_links']),
        'urgent_keywords': int(row['num_urgent_keywords']),
        'sensitive_request': bool(unsafe_sensitive_request),
        'intent': intent_signal,
    }

    return {
        'prediction': prediction_label,
        'confidence': confidence,
        'features': row,
        'risk_level': risk_level,
        'final_decision_reason': final_decision_reason,
        'supporting_signals': supporting_signals[:6],
        'reasons': supporting_signals[:6],
        'detected_signals': detected_signals,
    }

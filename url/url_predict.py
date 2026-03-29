from urllib.parse import urlparse

import pandas as pd

from models.load_models import SAFE_CLASS_THRESHOLD, model, model_feature_names
from url.url_features import domain_age_days, extract_features, ssl_certificate_status
from url.url_rules import (
    build_feature_diagnostics,
    build_reason_summary,
    compute_risk_level,
    high_risk_overlay,
)


def build_prediction_response(url):
    extracted_features = extract_features(url)

    if model_feature_names and len(model_feature_names) == len(extracted_features):
        model_input = pd.DataFrame([extracted_features], columns=model_feature_names)
    else:
        model_input = [extracted_features]

    class_probabilities = model.predict_proba(model_input)[0]
    classes = list(model.classes_)

    safe_probability = 0.0
    phishing_probability = 0.0
    if 1 in classes:
        safe_probability = float(class_probabilities[classes.index(1)])
    if 0 in classes:
        phishing_probability = float(class_probabilities[classes.index(0)])

    threshold_decision = 'Safe' if safe_probability >= SAFE_CLASS_THRESHOLD else 'Phishing'
    high_risk = high_risk_overlay(url, extracted_features)

    if high_risk['triggered']:
        final_result = 'Phishing'
        decision_source = 'high_risk_overlay'
    else:
        final_result = threshold_decision
        decision_source = 'probability_threshold'

    feature_diagnostics = build_feature_diagnostics(extracted_features)
    top_risky = [d for d in feature_diagnostics if d['risk_contribution'] > 0][:8]
    risk_level = compute_risk_level(final_result, phishing_probability, high_risk)
    reason_summary = build_reason_summary(
        final_result,
        high_risk,
        top_risky,
        safe_probability,
        phishing_probability,
    )

    parsed_url = urlparse(url)
    host = parsed_url.netloc.split(':')[0].lower()
    age_days, _ = domain_age_days(host)
    ssl_info = ssl_certificate_status(host)

    return {
        'result': final_result,
        'url': url,
        'confidence': float(max(class_probabilities)),
        'risk_level': risk_level,
        'reasons': reason_summary,
        'domain_age_days': age_days,
        'has_ssl': ssl_info['has_ssl'],
        'ssl_valid': ssl_info['ssl_valid'],
        'ssl_issuer': ssl_info['ssl_issuer'],
        'ssl_valid_until': ssl_info['ssl_valid_until'],
        'ssl_error': ssl_info['ssl_error'],
        'features': extracted_features,
        'debug': {
            'safe_class_threshold': SAFE_CLASS_THRESHOLD,
            'decision_source': decision_source,
            'safe_probability': round(safe_probability, 6),
            'phishing_probability': round(phishing_probability, 6),
            'high_risk_overlay': high_risk,
            'top_risky_features': top_risky,
            'feature_diagnostics': feature_diagnostics,
        },
    }

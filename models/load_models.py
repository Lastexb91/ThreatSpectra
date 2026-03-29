import joblib

SAFE_CLASS_THRESHOLD = 0.65
HIGH_RISK_MIN_SIGNALS = 2


try:
    model_data = joblib.load('website_detection/phishing_model_complete.pkl')
    if isinstance(model_data, dict):
        model = model_data.get('model')
        model_feature_names = model_data.get('features', [])
    else:
        model = model_data
        model_feature_names = []
    print('Model loaded successfully!')
except Exception as e:
    print(f'Error loading model: {e}')
    model = None
    model_feature_names = []


def _load_email_artifacts():
    return joblib.load('email_detection/email_phishing_model.pkl')


EMAIL_FEATURE_COLUMNS = [
    'num_words',
    'num_unique_words',
    'num_stopwords',
    'num_links',
    'num_unique_domains',
    'num_email_addresses',
    'num_spelling_errors',
    'num_urgent_keywords',
]


try:
    email_model = _load_email_artifacts()
    email_feature_columns = EMAIL_FEATURE_COLUMNS
    print('Email model loaded successfully!')
except Exception as e:
    print(f'Email model loading error: {e}')
    email_model = None
    email_feature_columns = EMAIL_FEATURE_COLUMNS


def _load_sms_artifacts():
    model_paths = [
        'sms_detection/sms_phishing_model.pkl',
        'sms_phishing_model.pkl',
    ]

    loaded_model = None
    loaded_tfidf = None

    for model_path in model_paths:
        try:
            payload = joblib.load(model_path)
            if isinstance(payload, dict):
                loaded_model = payload.get('model')
                loaded_tfidf = payload.get('tfidf')
            if loaded_model is not None and loaded_tfidf is not None:
                break
        except Exception:
            continue

    return loaded_model, loaded_tfidf


sms_model, sms_tfidf = _load_sms_artifacts()
if sms_model is not None and sms_tfidf is not None:
    print('SMS model loaded successfully!')
else:
    print('SMS model could not be loaded with tfidf vectorizer.')

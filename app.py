import re
import importlib.util
import warnings
import sys
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from models.load_models import email_model, model, sms_model, sms_tfidf
from sms.sms_predict import predict_sms_with_tfidf
from url.url_predict import build_prediction_response
from utils.helpers import (
    extract_qr_urls_from_upload,
    is_valid_url,
    load_env_file,
    send_contact_email,
)

warnings.filterwarnings('ignore')
load_env_file()

PROJECT_ROOT = Path(__file__).resolve().parent
EMAIL_SRC_DIR = PROJECT_ROOT / 'email'
EMAIL_PREDICT_PATH = EMAIL_SRC_DIR / 'email_predict.py'
EMAIL_RULES_PATH = EMAIL_SRC_DIR / 'email_rules.py'
EMAIL_FEATURES_PATH = EMAIL_SRC_DIR / 'email_features.py'


def _load_email_module(module_name, module_path):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_email_features_module = _load_email_module('email_features', EMAIL_FEATURES_PATH)
_email_rules_module = _load_email_module('email_rules', EMAIL_RULES_PATH)
_email_predict_module = _load_email_module('email_predict', EMAIL_PREDICT_PATH)
predict_email_with_features = _email_predict_module.predict_email_with_features

app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static/images', 'shield.jpg', mimetype='image/jpeg')


@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()

        if not data or 'url' not in data:
            return jsonify({
                'error': 'Invalid input. Please provide a URL.',
                'result': None,
            }), 400

        url = data['url'].strip()

        if not url:
            return jsonify({
                'error': 'URL cannot be empty.',
                'result': None,
            }), 400

        if not is_valid_url(url):
            return jsonify({
                'error': 'Invalid URL format. Please enter a valid URL.',
                'result': None,
            }), 400

        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if model is None:
            return jsonify({
                'error': 'Model not loaded. Please check the server.',
                'result': None,
            }), 500

        prediction_payload = build_prediction_response(url)
        return jsonify(prediction_payload), 200

    except Exception as e:
        print(f'Error in prediction: {e}')
        return jsonify({
            'error': f'An error occurred: {str(e)}',
            'result': None,
        }), 500


@app.route('/predict_email', methods=['POST'])
def predict_email():
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({
                'error': 'Invalid input. Please provide email text in the email field.',
                'prediction': None,
            }), 400

        email_text = str(data.get('email', '')).strip()
        if not email_text:
            return jsonify({
                'error': 'Email text cannot be empty.',
                'prediction': None,
            }), 400

        if email_model is None:
            return jsonify({
                'error': 'Email model not loaded correctly. Ensure email_detection/email_phishing_model.pkl exists and is a valid model file.',
                'prediction': None,
            }), 500

        prediction_payload = predict_email_with_features(email_text)

        response_payload = {
            'prediction': prediction_payload['prediction'],
            'confidence': prediction_payload['confidence'],
            'result': prediction_payload['prediction'],
            'risk_level': prediction_payload.get('risk_level'),
            'final_decision_reason': prediction_payload.get('final_decision_reason'),
            'supporting_signals': prediction_payload.get('supporting_signals', []),
            'reasons': prediction_payload.get('reasons', []),
            'detected_signals': prediction_payload.get('detected_signals', {}),
            'input_type': 'email',
            'text_preview': email_text[:260],
            'debug': prediction_payload.get('debug', {}),
        }

        return jsonify(response_payload), 200

    except Exception as e:
        print(f'Error in email prediction: {e}')
        return jsonify({
            'error': f'An error occurred while analyzing email text: {str(e)}',
            'prediction': None,
        }), 500


@app.route('/predict/email', methods=['POST'])
def predict_email_legacy():
    try:
        data = request.get_json() or {}
        text = str(data.get('text', '')).strip()
        if not text:
            return jsonify({'error': 'Email text cannot be empty.', 'prediction': None}), 400

        if email_model is None:
            return jsonify({
                'error': 'Email model not loaded correctly. Ensure email_detection/email_phishing_model.pkl exists and is a valid model file.',
                'prediction': None,
            }), 500

        prediction_payload = predict_email_with_features(text)
        return jsonify({
            'prediction': prediction_payload['prediction'],
            'confidence': prediction_payload['confidence'],
            'result': prediction_payload['prediction'],
            'risk_level': prediction_payload.get('risk_level'),
            'final_decision_reason': prediction_payload.get('final_decision_reason'),
            'supporting_signals': prediction_payload.get('supporting_signals', []),
            'reasons': prediction_payload.get('reasons', []),
            'detected_signals': prediction_payload.get('detected_signals', {}),
            'input_type': 'email',
            'text_preview': text[:200],
        }), 200
    except Exception as e:
        print(f'Error in legacy email prediction: {e}')
        return jsonify({'error': f'An error occurred while analyzing email text: {str(e)}', 'prediction': None}), 500


@app.route('/predict/sms', methods=['POST'])
def predict_sms():
    try:
        data = request.get_json()
        if not data or 'text' not in data:
            return jsonify({
                'error': 'Invalid input. Please provide SMS text in the text field.',
                'prediction': None,
            }), 400

        sms_text = str(data.get('text', '')).strip()
        if not sms_text:
            return jsonify({
                'error': 'SMS text cannot be empty.',
                'prediction': None,
            }), 400

        if sms_model is None or sms_tfidf is None:
            return jsonify({
                'error': 'SMS model not loaded correctly. Ensure sms_phishing_model.pkl contains model and tfidf.',
                'prediction': None,
            }), 500

        prediction_payload = predict_sms_with_tfidf(sms_text)
        response_payload = {
            'prediction': prediction_payload['prediction'],
        }
        if prediction_payload['confidence'] is not None:
            response_payload['confidence'] = prediction_payload['confidence']

        return jsonify(response_payload), 200

    except Exception as e:
        print(f'Error in SMS prediction: {e}')
        return jsonify({
            'error': f'An error occurred while analyzing SMS text: {str(e)}',
            'prediction': None,
        }), 500


@app.route('/predict-qr', methods=['POST'])
def predict_qr():
    try:
        if 'qr_image' not in request.files:
            return jsonify({
                'error': 'No image uploaded. Please upload a QR image file.',
                'result': None,
            }), 400

        uploaded_file = request.files['qr_image']
        if uploaded_file is None or not uploaded_file.filename:
            return jsonify({
                'error': 'No image selected. Please choose a QR image.',
                'result': None,
            }), 400

        if model is None:
            return jsonify({
                'error': 'Model not loaded. Please check the server.',
                'result': None,
            }), 500

        decoded_values = extract_qr_urls_from_upload(uploaded_file)
        if not decoded_values:
            return jsonify({
                'error': 'No QR code detected in the uploaded image.',
                'result': None,
            }), 400

        if len(decoded_values) > 1:
            return jsonify({
                'error': 'Multiple QR codes detected. Please upload an image with a single QR code.',
                'result': None,
                'decoded_values': decoded_values,
            }), 400

        extracted_url = decoded_values[0].strip()
        if not extracted_url.startswith(('http://', 'https://')):
            return jsonify({
                'error': 'QR detected, but it does not contain a valid http/https URL.',
                'result': None,
                'decoded_value': extracted_url,
            }), 400

        if not is_valid_url(extracted_url):
            return jsonify({
                'error': 'QR detected, but extracted URL format is invalid.',
                'result': None,
                'decoded_value': extracted_url,
            }), 400

        prediction_payload = build_prediction_response(extracted_url)
        prediction_payload['input_type'] = 'qr'
        prediction_payload['decoded_url'] = extracted_url
        return jsonify(prediction_payload), 200

    except Exception as e:
        print(f'Error in QR prediction: {e}')
        return jsonify({
            'error': f'An error occurred while processing QR image: {str(e)}',
            'result': None,
        }), 500


@app.route('/contact/send', methods=['POST'])
def send_contact_message():
    try:
        data = request.get_json() or {}

        name = str(data.get('name', '')).strip()
        email = str(data.get('email', '')).strip()
        message = str(data.get('message', '')).strip()

        if not name or not email or not message:
            return jsonify({'error': 'Name, email, and message are required.'}), 400

        if len(name) > 120 or len(email) > 200 or len(message) > 5000:
            return jsonify({'error': 'Input is too long. Please shorten your message.'}), 400

        if not re.fullmatch(r'^[^\s@]+@[^\s@]+\.[^\s@]+$', email):
            return jsonify({'error': 'Please provide a valid email address.'}), 400

        send_contact_email(name=name, sender_email=email, message_text=message)
        return jsonify({'success': True, 'message': 'Your message has been sent successfully.'}), 200

    except RuntimeError as conf_error:
        print(f'Contact mail config error: {conf_error}')
        return jsonify({'error': str(conf_error)}), 500
    except Exception as e:
        print(f'Error sending contact email: {e}')
        return jsonify({'error': 'Failed to send your message. Please try again later.'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

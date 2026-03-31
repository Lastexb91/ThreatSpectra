// Initialize AOS with enhanced settings
AOS.init({
    duration: 1000,
    easing: 'ease-in-out-cubic',
    once: false,
    mirror: false,
    offset: 100,
    delay: 0,
    anchorPlacement: 'top-bottom'
});

// Wait for DOM to be ready before accessing elements
document.addEventListener('DOMContentLoaded', function() {
    // Enhanced navbar scroll effect
    const navbar = document.querySelector('.navbar');
    let scrolled = false;

    if (navbar) {
        window.addEventListener('scroll', () => {
            const scrollTop = window.scrollY;
            
            if (scrollTop > 50 && !scrolled) {
                navbar.classList.add('scrolled');
                scrolled = true;
            } else if (scrollTop <= 50 && scrolled) {
                navbar.classList.remove('scrolled');
                scrolled = false;
            }
        });
    }
    
    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

// URL Check functionality with enhanced animations
let urlInput, checkButton, result, qrImageInput, checkQrButton;
let emailInput, checkEmailButton, smsInput, checkSmsButton;
let modeUrlBtn, modeQrBtn, modeEmailBtn, modeSmsBtn, urlCheckPanel, qrCheckPanel, emailCheckPanel, smsCheckPanel;
let qrExamplesGrid;

const EXAMPLE_URLS = {
    trusted: [
        { url: 'https://www.google.com', note: 'Official Google Search' },
        { url: 'https://www.amazon.com', note: 'Amazon Shopping' },
        { url: 'https://www.microsoft.com', note: 'Microsoft Official' },
        { url: 'https://www.facebook.com', note: 'Facebook Social' }
    ],
    malicious: [
        { url: 'http://g00gle.security-check.com', note: 'Fake Google Login' },
        { url: 'http://amaz0n.account-verify.net', note: 'Amazon Impersonator' },
        { url: 'http://faceb00k.login-secure.com', note: 'Facebook Phishing' },
        { url: 'http://paypa1.account-update.org', note: 'PayPal Scam' }
    ]
};

const EXAMPLE_EMAILS = {
    trusted: [
        {
            note: 'Monthly statement notice (legitimate)',
            text: 'Subject: Your Monthly Account Statement is Ready. Hello John, your monthly account statement for August is now available. You can securely access it through our official website: https://www.bankofamerica.com. If you have any questions, please contact our support team. Best regards, Bank of America Customer Support.'
        },
        {
            note: 'Order confirmation (legitimate)',
            text: 'Subject: Your Recent Order Confirmation – Thank You for Your Purchase. Hi John, thank you for your recent order with us. This email confirms your purchase has been successfully processed. Order Details: Order ID #A49382X, Date September 12, 2026, Payment Method Visa ending in 4582. You can view your order status or download your invoice through our official website: https://www.amazon.com. For assistance, contact support@amazon.com. Best regards, Amazon Customer Service Team.'
        },
        {
            note: 'Security advisory (legitimate)',
            text: 'Subject: Security Advisory from Account Support. Dear Customer, this is an informational notice about recent online safety tips. Please continue signing in only from our official website and never share your password by email. This message does not require any immediate action.'
        }
    ],
    malicious: [
        {
            note: 'Account suspension scam',
            text: 'Subject: Immediate Action Required – Account Suspension Notice. Dear Customer, we detected unusual activity on your account and it has been temporarily restricted. To restore access, verify your account immediately using this link: https://secure-verification-g00gle.com/account/review. Failure to verify within 24 hours will lead to permanent suspension.'
        },
        {
            note: 'Credential harvest scam',
            text: 'Subject: Urgent Verification Required. Your mailbox will be deactivated unless you confirm your password, OTP, and PIN now. Click here to continue account validation immediately.'
        },
        {
            note: 'Billing/payment scam',
            text: 'Subject: Payment Failed - Update Required. We could not process your payment. Update your card and CVV now at http://billing-verification-secure.com to avoid service interruption.'
        }
    ]
};

const EXAMPLE_SMS = {
    trusted: [
        {
            note: 'Official bank fraud advisory (legitimate)',
            text: 'SBI Alert: A login was detected from a new device. If this was not you, review recent activity only via https://www.onlinesbi.sbi. For your safety, never share OTP, PIN, or password with anyone.'
        },
        {
            note: 'UPI debit notification (legitimate)',
            text: 'ICICI Bank: INR 12,450 debited via UPI Ref 438921. If not done by you, contact customer care using official channels only. Do not share OTP or card details.'
        },
        {
            note: 'Credit card control alert (legitimate)',
            text: 'HDFC Bank: Your card was temporarily blocked after multiple incorrect PIN attempts. To unblock, call official helpline listed on the card. Never share CVV/OTP over calls or links.'
        },
        {
            note: 'Delivery OTP policy reminder (legitimate)',
            text: 'Flipkart: Your package FK-99201 is out for delivery. Delivery agent will never ask for UPI PIN. Share only delivery OTP at doorstep.'
        }
    ],
    malicious: [
        {
            note: 'Lookalike banking domain scam',
            text: 'HDFC Security Team: Account restricted after review. Restore immediately at https://hdfc-secure-access.co.in/login. Link expires in 10 minutes.'
        },
        {
            note: 'KYC suspension pressure scam',
            text: 'Axis Bank: KYC failed. Your account will be frozen today unless you re-verify now: http://axis-kyc-update.net/confirm. Enter OTP to continue.'
        },
        {
            note: 'Reward plus credential theft scam',
            text: 'Congratulations! You won INR 25,000 cashback. Claim now by confirming bank username, password, and OTP at https://reward-wallet-claim.com'
        },
        {
            note: 'Fake card reactivation scam',
            text: 'SBI Notice: Debit card disabled due to security issue. Reactivate instantly at http://sbi-card-restore.help and submit CVV + PIN.'
        }
    ]
};

// Initialize elements after DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    urlInput = document.getElementById('urlInput');
    checkButton = document.getElementById('checkButton');
    qrImageInput = document.getElementById('qrImageInput');
    checkQrButton = document.getElementById('checkQrButton');
    emailInput = document.getElementById('emailInput');
    checkEmailButton = document.getElementById('checkEmailButton');
    smsInput = document.getElementById('smsInput');
    checkSmsButton = document.getElementById('checkSmsButton');
    modeUrlBtn = document.getElementById('modeUrlBtn');
    modeQrBtn = document.getElementById('modeQrBtn');
    modeEmailBtn = document.getElementById('modeEmailBtn');
    modeSmsBtn = document.getElementById('modeSmsBtn');
    urlCheckPanel = document.getElementById('urlCheckPanel');
    qrCheckPanel = document.getElementById('qrCheckPanel');
    emailCheckPanel = document.getElementById('emailCheckPanel');
    smsCheckPanel = document.getElementById('smsCheckPanel');
    qrExamplesGrid = document.getElementById('qrExamplesGrid');
    result = document.getElementById('result');
    setupExamplesQuickBar();
    setupEmailExamplesQuickBar();
    setupSmsExamplesQuickBar();
    setupModeSwitcher();
    renderQrExamples();
    
    // Only add event listeners if elements exist
    if (checkButton && urlInput && result) {
        checkButton.addEventListener('click', handleUrlCheck);
        
        // Enable checking URL on Enter key press
        urlInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                checkButton.click();
            }
        });
        
        // Enhanced URL input validation
        urlInput.addEventListener('input', function() {
            const url = this.value.trim();
            if (url && !isValidUrl(url)) {
                this.style.borderColor = '#f56565';
                this.style.boxShadow = '0 0 0 3px rgba(245, 101, 101, 0.2)';
            } else {
                this.style.borderColor = '';
                this.style.boxShadow = '';
            }
        });
    } else {
        console.warn('URL checker elements not found. Make sure the HTML has the correct IDs.');
    }

    if (checkQrButton && qrImageInput && result) {
        checkQrButton.addEventListener('click', handleQrCheck);
    }

    if (checkEmailButton && emailInput && result) {
        checkEmailButton.addEventListener('click', handleEmailCheck);
    }

    if (checkSmsButton && smsInput && result) {
        checkSmsButton.addEventListener('click', handleSmsCheck);
    }
});

function copyTextToClipboard(value) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(value);
    }

    const tempInput = document.createElement('textarea');
    tempInput.value = value;
    tempInput.setAttribute('readonly', '');
    tempInput.style.position = 'absolute';
    tempInput.style.left = '-9999px';
    document.body.appendChild(tempInput);
    tempInput.select();
    document.execCommand('copy');
    document.body.removeChild(tempInput);
    return Promise.resolve();
}

function setupExamplesQuickBar() {
    const quickBar = document.getElementById('examplesQuickBar');
    const popup = document.getElementById('examplesPopup');
    if (!quickBar || !popup) return;

    const buttons = quickBar.querySelectorAll('.example-pill');

    const hidePopup = () => {
        popup.style.display = 'none';
        popup.innerHTML = '';
        buttons.forEach((button) => button.classList.remove('active'));
    };

    const showPopup = (group) => {
        const selected = EXAMPLE_URLS[group] || [];
        const heading = group === 'trusted' ? 'Trusted URL Examples' : 'Malicious URL Examples';

        popup.innerHTML = `
            <div class="examples-popup-header">
                <h4 class="examples-popup-title">${heading}</h4>
                <button type="button" class="examples-popup-close" id="examplesPopupClose" aria-label="Close examples">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            ${selected.map((item) => `
                <div class="example-url-item">
                    <div class="example-url-main">
                        <span class="example-url-text">${escapeHtml(item.url)}</span>
                        <span class="example-url-note">${escapeHtml(item.note)}</span>
                    </div>
                    <button type="button" class="copy-example-btn" data-copy-url="${escapeHtml(item.url)}">
                        <i class="fas fa-copy me-1"></i>Copy
                    </button>
                </div>
            `).join('')}
        `;

        popup.style.display = 'block';
        buttons.forEach((button) => {
            button.classList.toggle('active', button.dataset.group === group);
        });

        const closeButton = document.getElementById('examplesPopupClose');
        if (closeButton) {
            closeButton.addEventListener('click', hidePopup);
        }
    };

    quickBar.addEventListener('click', (event) => {
        const trigger = event.target.closest('.example-pill');
        if (!trigger) return;

        const group = trigger.dataset.group;
        const isActive = trigger.classList.contains('active');
        if (isActive) {
            hidePopup();
            return;
        }
        showPopup(group);
    });

    popup.addEventListener('click', (event) => {
        const copyButton = event.target.closest('.copy-example-btn');
        if (!copyButton) return;

        const url = copyButton.getAttribute('data-copy-url');
        if (!url) return;

        copyTextToClipboard(url)
            .then(() => showToast('URL copied. Paste it in the checker input.', 'success'))
            .catch(() => showToast('Copy failed. Please copy manually.', 'error'));
    });

    document.addEventListener('click', (event) => {
        if (popup.style.display === 'none') return;
        if (quickBar.contains(event.target) || popup.contains(event.target)) return;
        hidePopup();
    });
}

function setupEmailExamplesQuickBar() {
    const quickBar = document.getElementById('emailExamplesQuickBar');
    const popup = document.getElementById('emailExamplesPopup');
    if (!quickBar || !popup || !emailInput) return;

    const buttons = quickBar.querySelectorAll('.example-pill');

    const hidePopup = () => {
        popup.style.display = 'none';
        popup.innerHTML = '';
        buttons.forEach((button) => button.classList.remove('active'));
    };

    const showPopup = (group) => {
        const selected = EXAMPLE_EMAILS[group] || [];
        const heading = group === 'trusted' ? 'Trusted Email Examples' : 'Malicious Email Examples';

        popup.innerHTML = `
            <div class="examples-popup-header">
                <h4 class="examples-popup-title">${heading}</h4>
                <button type="button" class="examples-popup-close" id="emailExamplesPopupClose" aria-label="Close email examples">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            ${selected.map((item) => `
                <div class="email-example-item">
                    <div class="email-example-main">
                        <span class="email-example-note">${escapeHtml(item.note)}</span>
                        <p class="email-example-text">${escapeHtml(item.text)}</p>
                    </div>
                    <div class="email-example-actions">
                        <button type="button" class="btn btn-sm btn-gradient use-email-example-btn" data-email-text="${escapeHtml(item.text)}">
                            <i class="fas fa-pen me-1"></i>Use
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-light copy-email-example-btn" data-email-text="${escapeHtml(item.text)}">
                            <i class="fas fa-copy me-1"></i>Copy
                        </button>
                    </div>
                </div>
            `).join('')}
        `;

        popup.style.display = 'block';
        buttons.forEach((button) => {
            button.classList.toggle('active', button.dataset.group === group);
        });

        const closeButton = document.getElementById('emailExamplesPopupClose');
        if (closeButton) {
            closeButton.addEventListener('click', hidePopup);
        }
    };

    quickBar.addEventListener('click', (event) => {
        const trigger = event.target.closest('.example-pill');
        if (!trigger) return;

        const group = trigger.dataset.group;
        const isActive = trigger.classList.contains('active');
        if (isActive) {
            hidePopup();
            return;
        }
        showPopup(group);
    });

    popup.addEventListener('click', (event) => {
        const useButton = event.target.closest('.use-email-example-btn');
        if (useButton) {
            const text = useButton.getAttribute('data-email-text') || '';
            emailInput.value = text;
            emailInput.focus();
            showToast('Email example loaded in the input box.', 'success');
            return;
        }

        const copyButton = event.target.closest('.copy-email-example-btn');
        if (copyButton) {
            const text = copyButton.getAttribute('data-email-text') || '';
            copyTextToClipboard(text)
                .then(() => showToast('Email example copied.', 'success'))
                .catch(() => showToast('Copy failed. Please copy manually.', 'error'));
        }
    });

    document.addEventListener('click', (event) => {
        if (popup.style.display === 'none') return;
        if (quickBar.contains(event.target) || popup.contains(event.target)) return;
        hidePopup();
    });
}

function setupSmsExamplesQuickBar() {
    const quickBar = document.getElementById('smsExamplesQuickBar');
    const popup = document.getElementById('smsExamplesPopup');
    if (!quickBar || !popup || !smsInput) return;

    const buttons = quickBar.querySelectorAll('.example-pill');

    const hidePopup = () => {
        popup.style.display = 'none';
        popup.innerHTML = '';
        buttons.forEach((button) => button.classList.remove('active'));
    };

    const showPopup = (group) => {
        const selected = EXAMPLE_SMS[group] || [];
        const heading = group === 'trusted' ? 'Trusted SMS Examples' : 'Malicious SMS Examples';

        popup.innerHTML = `
            <div class="examples-popup-header">
                <h4 class="examples-popup-title">${heading}</h4>
                <button type="button" class="examples-popup-close" id="smsExamplesPopupClose" aria-label="Close sms examples">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            ${selected.map((item) => `
                <div class="email-example-item">
                    <div class="email-example-main">
                        <span class="email-example-note">${escapeHtml(item.note)}</span>
                        <p class="email-example-text">${escapeHtml(item.text)}</p>
                    </div>
                    <div class="email-example-actions">
                        <button type="button" class="btn btn-sm btn-gradient use-sms-example-btn" data-sms-text="${escapeHtml(item.text)}">
                            <i class="fas fa-pen me-1"></i>Use
                        </button>
                        <button type="button" class="btn btn-sm btn-outline-light copy-sms-example-btn" data-sms-text="${escapeHtml(item.text)}">
                            <i class="fas fa-copy me-1"></i>Copy
                        </button>
                    </div>
                </div>
            `).join('')}
        `;

        popup.style.display = 'block';
        buttons.forEach((button) => {
            button.classList.toggle('active', button.dataset.group === group);
        });

        const closeButton = document.getElementById('smsExamplesPopupClose');
        if (closeButton) {
            closeButton.addEventListener('click', hidePopup);
        }
    };

    quickBar.addEventListener('click', (event) => {
        const trigger = event.target.closest('.example-pill');
        if (!trigger) return;

        const group = trigger.dataset.group;
        const isActive = trigger.classList.contains('active');
        if (isActive) {
            hidePopup();
            return;
        }
        showPopup(group);
    });

    popup.addEventListener('click', (event) => {
        const useButton = event.target.closest('.use-sms-example-btn');
        if (useButton) {
            const text = useButton.getAttribute('data-sms-text') || '';
            smsInput.value = text;
            smsInput.focus();
            showToast('SMS example loaded in the input box.', 'success');
            return;
        }

        const copyButton = event.target.closest('.copy-sms-example-btn');
        if (copyButton) {
            const text = copyButton.getAttribute('data-sms-text') || '';
            copyTextToClipboard(text)
                .then(() => showToast('SMS example copied.', 'success'))
                .catch(() => showToast('Copy failed. Please copy manually.', 'error'));
        }
    });

    document.addEventListener('click', (event) => {
        if (popup.style.display === 'none') return;
        if (quickBar.contains(event.target) || popup.contains(event.target)) return;
        hidePopup();
    });
}

function setupModeSwitcher() {
    if (!modeUrlBtn || !modeQrBtn || !modeEmailBtn || !modeSmsBtn || !urlCheckPanel || !qrCheckPanel || !emailCheckPanel || !smsCheckPanel) return;

    const setMode = (mode) => {
        const isUrl = mode === 'url';
        const isQr = mode === 'qr';
        const isEmail = mode === 'email';
        const isSms = mode === 'sms';

        modeUrlBtn.classList.toggle('active', isUrl);
        modeQrBtn.classList.toggle('active', isQr);
        modeEmailBtn.classList.toggle('active', isEmail);
        modeSmsBtn.classList.toggle('active', isSms);
        modeUrlBtn.setAttribute('aria-selected', String(isUrl));
        modeQrBtn.setAttribute('aria-selected', String(isQr));
        modeEmailBtn.setAttribute('aria-selected', String(isEmail));
        modeSmsBtn.setAttribute('aria-selected', String(isSms));

        urlCheckPanel.classList.toggle('active', isUrl);
        qrCheckPanel.classList.toggle('active', isQr);
        emailCheckPanel.classList.toggle('active', isEmail);
        smsCheckPanel.classList.toggle('active', isSms);

        if (result) {
            result.style.display = 'none';
            result.innerHTML = '';
        }

        if (isUrl && urlInput) {
            urlInput.focus();
        }
        if (isEmail && emailInput) {
            emailInput.focus();
        }
        if (isSms && smsInput) {
            smsInput.focus();
        }
    };

    modeUrlBtn.addEventListener('click', () => setMode('url'));
    modeQrBtn.addEventListener('click', () => setMode('qr'));
    modeEmailBtn.addEventListener('click', () => setMode('email'));
    modeSmsBtn.addEventListener('click', () => setMode('sms'));
}

function renderQrExamples() {
    if (!qrExamplesGrid) return;

    const allExamples = [
        ...EXAMPLE_URLS.trusted.map((item) => ({ ...item, type: 'trusted' })),
        ...EXAMPLE_URLS.malicious.map((item) => ({ ...item, type: 'malicious' }))
    ];

    qrExamplesGrid.innerHTML = allExamples.map((item, index) => `
        <div class="qr-example-card ${item.type}">
            <div class="qr-example-top">
                <span class="qr-type-badge ${item.type}">${item.type === 'trusted' ? 'Trusted' : 'Malicious'}</span>
                <span class="qr-example-note">${escapeHtml(item.note)}</span>
            </div>
            <div class="qr-code-box" id="qrCode_${index}"></div>
            <div class="qr-example-url">${escapeHtml(item.url)}</div>
            <a class="btn btn-sm btn-outline-light download-qr-btn" href="#" data-qr-id="qrCode_${index}" data-file-name="${item.type}_example_${index + 1}.png">
                <i class="fas fa-download me-1"></i>Download QR
            </a>
        </div>
    `).join('');

    if (typeof QRCode !== 'undefined') {
        allExamples.forEach((item, index) => {
            const mountNode = document.getElementById(`qrCode_${index}`);
            if (!mountNode) return;
            new QRCode(mountNode, {
                text: item.url,
                width: 128,
                height: 128,
                colorDark: '#0a1117',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.M,
            });
        });
    }

    qrExamplesGrid.addEventListener('click', (event) => {
        const downloadButton = event.target.closest('.download-qr-btn');
        if (!downloadButton) return;
        event.preventDefault();

        const qrId = downloadButton.getAttribute('data-qr-id');
        const fileName = downloadButton.getAttribute('data-file-name') || 'qr-example.png';
        const container = qrId ? document.getElementById(qrId) : null;
        if (!container) return;

        const canvas = container.querySelector('canvas');
        const qrImg = container.querySelector('img');
        let dataUrl = null;

        if (canvas && typeof canvas.toDataURL === 'function') {
            dataUrl = canvas.toDataURL('image/png');
        } else if (qrImg && qrImg.src) {
            dataUrl = qrImg.src;
        }

        if (!dataUrl) {
            showToast('Unable to generate download for this QR.', 'error');
            return;
        }

        const tempLink = document.createElement('a');
        tempLink.href = dataUrl;
        tempLink.download = fileName;
        document.body.appendChild(tempLink);
        tempLink.click();
        tempLink.remove();
    });
}

function showLoading() {
    const typedUrl = escapeHtml((urlInput && urlInput.value ? urlInput.value : '').trim());
    result.innerHTML = `
        <div class="result-card result-card-modern loading-state">
            <div class="modern-result-header">
                <i class="fas fa-spinner fa-spin"></i>
                <h3>Analyzing URL</h3>
                <p>${typedUrl || 'Preparing analysis...'}</p>
            </div>
            <div class="modern-result-body">
                <div class="modern-result-column">
                    <h5><i class="fas fa-chart-line"></i>Risk Assessment</h5>
                    <div class="modern-progress-track">
                        <div class="modern-progress-fill loading-bar" style="width: 45%"></div>
                    </div>
                    <div class="risk-meta-row">
                        <span class="risk-label risk-medium">Analyzing...</span>
                        <span class="risk-value">--</span>
                    </div>
                </div>
                <div class="modern-result-column">
                    <h5><i class="fas fa-cogs"></i>Detection Methods</h5>
                    <div class="method-badge-wrap">
                        <span class="method-pill"><i class="fas fa-robot"></i>Model Inference</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    result.style.display = 'block';
    
    // Add loading sound effect (optional)
    playSound('loading');
}

function showQrLoading(fileName) {
    const safeName = escapeHtml(fileName || 'QR image');
    result.innerHTML = `
        <div class="result-card result-card-modern loading-state">
            <div class="modern-result-header">
                <i class="fas fa-spinner fa-spin"></i>
                <h3>Decoding QR Image</h3>
                <p>${safeName}</p>
            </div>
            <div class="modern-result-body">
                <div class="modern-result-column">
                    <h5><i class="fas fa-qrcode"></i>QR Extraction</h5>
                    <div class="modern-progress-track">
                        <div class="modern-progress-fill loading-bar" style="width: 55%"></div>
                    </div>
                    <div class="risk-meta-row">
                        <span class="risk-label risk-medium">Decoding and analyzing...</span>
                        <span class="risk-value">--</span>
                    </div>
                </div>
                <div class="modern-result-column">
                    <h5><i class="fas fa-cogs"></i>Detection Methods</h5>
                    <div class="method-badge-wrap">
                        <span class="method-pill"><i class="fas fa-qrcode"></i>QR Decode</span>
                        <span class="method-pill"><i class="fas fa-robot"></i>URL Model Inference</span>
                    </div>
                </div>
            </div>
        </div>
    `;
    result.style.display = 'block';
    playSound('loading');
}

function showError(message) {
    result.innerHTML = `
        <div class="analysis-card error">
            <div class="text-center p-4">
                <i class="fas fa-exclamation-circle text-danger fa-4x mb-3 bounce"></i>
                <h4 class="text-danger mb-2">Analysis Error</h4>
                <p class="text-light opacity-75">${message}</p>
                <button class="btn btn-outline-light mt-3" onclick="checkButton.click()">
                    <i class="fas fa-redo me-2"></i>Try Again
                </button>
            </div>
        </div>
    `;
    result.style.display = 'block';
    
    // Add error sound effect (optional)
    playSound('error');
}

function clamp(value, min, max) {
    return Math.max(min, Math.min(max, value));
}

function escapeHtml(raw) {
    if (typeof raw !== 'string') return '';
    return raw
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/\"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function getRiskPresentation(riskScore) {
    if (riskScore >= 70) return { label: 'High Risk', className: 'risk-high', iconClass: 'text-danger' };
    if (riskScore >= 35) return { label: 'Medium Risk', className: 'risk-medium', iconClass: 'text-warning' };
    return { label: 'Low Risk', className: 'risk-low', iconClass: 'text-success' };
}

function mapDetectionMethods(data) {
    const source = data && data.debug && data.debug.decision_source ? data.debug.decision_source : 'model_analysis';
    const mapped = {
        high_risk_overlay: 'High-Risk Overlay',
        probability_threshold: 'Probability Threshold',
        model_analysis: 'Rule-based Analysis'
    };
    return [mapped[source] || 'Rule-based Analysis'];
}

function resetUrlChecker() {
    if (!result || !urlInput) return;
    result.style.display = 'none';
    result.innerHTML = '';
    urlInput.value = '';
    urlInput.focus();
}

function showResult(data) {
    const isSafe = data.result === 'Safe';
    const statusClass = isSafe ? 'safe' : 'dangerous';
    const statusIcon = isSafe ? 'fa-check-square' : 'fa-triangle-exclamation';
    const confidence = Number(data.confidence || 0);
    const phishingProbability = typeof data.debug?.phishing_probability === 'number'
        ? data.debug.phishing_probability
        : (isSafe ? 1 - confidence : confidence);
    let riskScore = clamp(Number(phishingProbability) * 100, 1, 99);
    if (!isSafe) {
        const decisionSource = data?.debug?.decision_source;
        const riskLevel = String(data?.risk_level || '').toLowerCase();

        // Keep UI risk label aligned with phishing verdicts.
        if (decisionSource === 'high_risk_overlay') {
            riskScore = Math.max(riskScore, 75);
        }
        if (riskLevel === 'critical') {
            riskScore = Math.max(riskScore, 90);
        } else if (riskLevel === 'high') {
            riskScore = Math.max(riskScore, 75);
        } else if (riskLevel === 'medium') {
            riskScore = Math.max(riskScore, 55);
        }
    }
    const riskState = getRiskPresentation(riskScore);

    const detectionBadges = mapDetectionMethods(data)
        .map((method) => `<span class="method-pill"><i class="fas fa-robot"></i>${escapeHtml(method)}</span>`)
        .join('');

    const safeUrl = escapeHtml(data.url || 'N/A');
    const domainAge = Number.isFinite(Number(data.domain_age_days))
        ? `${Number(data.domain_age_days)} days`
        : 'Unknown';
    const hasSSL = Boolean(data.has_ssl);
    const sslValid = Boolean(data.ssl_valid);
    const sslSummary = hasSSL
        ? (sslValid ? 'Valid Certificate' : 'Certificate Invalid/Expired')
        : 'No certificate detected';
    const sslIssuer = data.ssl_issuer ? `Issuer: ${escapeHtml(data.ssl_issuer)}` : '';
    const sslValidUntil = data.ssl_valid_until
        ? `Valid until: ${escapeHtml(new Date(data.ssl_valid_until).toLocaleDateString())}`
        : '';
    const sslError = !hasSSL && data.ssl_error ? `Note: ${escapeHtml(data.ssl_error)}` : '';
    const sslDetailParts = [sslIssuer, sslValidUntil, sslError].filter(Boolean);

    result.innerHTML = `
        <div class="result-card result-card-modern analysis-card ${statusClass}">
            <div class="modern-result-header">
                <i class="fas ${statusIcon}"></i>
                <h3>${isSafe ? 'Safe Website' : 'Potential Threat Detected'}</h3>
                <p>${safeUrl}</p>
            </div>
            <div class="modern-result-body">
                <div class="modern-result-column">
                    <h5><i class="fas fa-chart-line"></i>Risk Assessment</h5>
                    <div class="modern-progress-track">
                        <div class="modern-progress-fill ${riskState.className}" data-width="${riskScore.toFixed(1)}"></div>
                    </div>
                    <div class="risk-meta-row">
                        <span class="risk-label ${riskState.className}">${riskState.label}</span>
                        <span class="risk-value">${riskScore.toFixed(1)}%</span>
                    </div>

                    <h5 class="mt-4"><i class="fas fa-globe"></i>Domain Information</h5>
                    <div class="domain-grid">
                        <div class="domain-item">
                            <i class="fas fa-calendar-alt"></i>
                            <span>Age: ${domainAge}</span>
                        </div>
                        <div class="domain-item">
                            <i class="fas fa-lock"></i>
                            <span>SSL: ${sslSummary}</span>
                        </div>
                        ${sslDetailParts.map((part) => `
                        <div class="domain-item">
                            <i class="fas fa-certificate"></i>
                            <span>${part}</span>
                        </div>
                        `).join('')}
                    </div>
                </div>

                <div class="modern-result-column">
                    <h5><i class="fas fa-cogs"></i>Detection Methods</h5>
                    <div class="method-badge-wrap">
                        ${detectionBadges}
                    </div>
                </div>
            </div>

            <div class="text-center mt-4">
                <button class="btn btn-outline-light btn-lg check-another-btn" type="button" onclick="resetUrlChecker()">
                    <i class="fas fa-search me-2"></i>Check Another URL
                </button>
            </div>
        </div>
    `;

    result.style.display = 'block';

    setTimeout(() => {
        const progressBar = result.querySelector('.modern-progress-fill');
        if (progressBar) {
            progressBar.style.width = `${progressBar.getAttribute('data-width')}%`;
        }
    }, 220);

    playSound(isSafe ? 'success' : 'warning');
}

function showEmailResult(data) {
    const verdict = data.prediction || data.result;
    const isSafe = verdict === 'Safe';
    const statusClass = isSafe ? 'safe' : 'dangerous';
    const statusIcon = isSafe ? 'fa-check-square' : 'fa-triangle-exclamation';
    const confidencePct = typeof data.confidence === 'number'
        ? clamp(Number(data.confidence) * 100, 0, 100)
        : 0;
    const confidence = typeof data.confidence === 'number'
        ? `${confidencePct.toFixed(1)}%`
        : 'N/A';
    const riskLevel = String(data.risk_level || (isSafe ? 'Low' : 'High'));
    const normalizedRisk = riskLevel.toLowerCase();
    const riskClass = normalizedRisk === 'high'
        ? 'risk-high'
        : (normalizedRisk === 'medium' ? 'risk-medium' : 'risk-low');
    const finalDecisionReason = escapeHtml(String(
        data.final_decision_reason
        || (isSafe ? 'No high-risk phishing pattern detected in the message.' : 'Potential phishing pattern detected.')
    ));
    const reasons = Array.isArray(data.supporting_signals) && data.supporting_signals.length
        ? data.supporting_signals
        : (Array.isArray(data.reasons) && data.reasons.length ? data.reasons : [
            'No suspicious links detected.',
            'No direct request for sensitive information detected.',
            'Informational/advisory content context identified.',
        ]);
    const signals = data.detected_signals || {};
    const links = Number.isFinite(Number(signals.links)) ? Number(signals.links) : 0;
    const urgentKeywords = Number.isFinite(Number(signals.urgent_keywords)) ? Number(signals.urgent_keywords) : 0;
    const sensitiveRequest = signals.sensitive_request ? 'Yes' : 'No';
    let intentLabel = String(signals.intent || 'Safe');

    let verdictLabel = verdict;
    if (normalizedRisk === 'medium') {
        verdictLabel = 'Safe';
        intentLabel = 'Safe';
    }
    const intent = escapeHtml(intentLabel);

    result.innerHTML = `
        <div class="result-card result-card-modern analysis-card ${statusClass}">
            <div class="modern-result-header">
                <i class="fas ${statusIcon}"></i>
                <h3>${escapeHtml(verdictLabel)} Email (${escapeHtml(riskLevel)} Risk)</h3>
                <p>Email text analysis completed</p>
            </div>
            <div class="modern-result-body">
                <div class="modern-result-column">
                    <h5><i class="fas fa-cogs"></i>Detection Methods</h5>
                    <div class="method-badge-wrap">
                        <span class="method-pill"><i class="fas fa-file-alt"></i>Text Preprocessing</span>
                        <span class="method-pill"><i class="fas fa-project-diagram"></i>Feature Extraction</span>
                        <span class="method-pill"><i class="fas fa-robot"></i>Email Model Inference</span>
                    </div>

                    <h5 class="mt-4"><i class="fas fa-sliders-h"></i>Confidence</h5>
                    <div class="modern-progress-track">
                        <div class="modern-progress-fill ${riskClass}" data-width="${confidencePct.toFixed(1)}"></div>
                    </div>
                    <div class="risk-meta-row mt-3">
                        <span class="risk-label ${riskClass}">${escapeHtml(verdictLabel)} (${escapeHtml(riskLevel)} Risk)</span>
                        <span class="risk-value">Confidence: ${confidence}</span>
                    </div>

                </div>

                <div class="modern-result-column">
                    <h5><i class="fas fa-bullseye"></i>Final Decision Reason</h5>
                    <p class="decision-reason-box"><i class="fas fa-exclamation-triangle me-2"></i>${finalDecisionReason}</p>

                    <h5 class="mt-4"><i class="fas fa-list-check"></i>Supporting Signals</h5>
                    <ul class="reason-list">
                        ${reasons.map((reason) => `<li><i class="fas fa-check-circle"></i>${escapeHtml(reason)}</li>`).join('')}
                    </ul>

                    <h5 class="mt-4"><i class="fas fa-signal"></i>Detected Signals</h5>
                    <ul class="signal-list">
                        <li><span>Links</span><strong>${links}</strong></li>
                        <li><span>Urgent Keywords</span><strong>${urgentKeywords}</strong></li>
                        <li><span>Sensitive Request</span><strong>${sensitiveRequest}</strong></li>
                        <li><span>Intent</span><strong>${intent}</strong></li>
                    </ul>
                </div>
            </div>
            <div class="text-center mt-4">
                <button class="btn btn-outline-light btn-lg check-another-btn" type="button" onclick="resetUrlChecker()">
                    <i class="fas fa-search me-2"></i>Check Another Input
                </button>
            </div>
        </div>
    `;

    result.style.display = 'block';
    setTimeout(() => {
        const progressBar = result.querySelector('.modern-progress-fill');
        if (progressBar) {
            progressBar.style.width = `${progressBar.getAttribute('data-width')}%`;
        }
    }, 220);
    playSound(isSafe ? 'success' : 'warning');
}

function showSmsResult(data, sourceText) {
    const verdict = data.prediction;
    const isSafe = verdict === 'Safe';
    const statusClass = isSafe ? 'safe' : 'dangerous';
    const statusIcon = isSafe ? 'fa-check-square' : 'fa-triangle-exclamation';
    const confidence = typeof data.confidence === 'number'
        ? `${(data.confidence * 100).toFixed(1)}%`
        : 'N/A';
    const preview = escapeHtml(sourceText || '');

    result.innerHTML = `
        <div class="result-card result-card-modern analysis-card ${statusClass}">
            <div class="modern-result-header">
                <i class="fas ${statusIcon}"></i>
                <h3>${isSafe ? 'Safe SMS' : 'Potential Phishing SMS'}</h3>
                <p>SMS text analysis completed</p>
            </div>
            <div class="modern-result-body">
                <div class="modern-result-column">
                    <h5><i class="fas fa-comment-dots"></i>SMS Preview</h5>
                    <p class="mb-0" style="opacity:0.9; line-height:1.6;">${preview || 'No preview available.'}</p>
                </div>
                <div class="modern-result-column">
                    <h5><i class="fas fa-cogs"></i>Detection Methods</h5>
                    <div class="method-badge-wrap">
                        <span class="method-pill"><i class="fas fa-file-alt"></i>Text Preprocessing</span>
                        <span class="method-pill"><i class="fas fa-project-diagram"></i>TF-IDF Vectorization</span>
                        <span class="method-pill"><i class="fas fa-robot"></i>SMS Model Inference</span>
                    </div>
                    <div class="risk-meta-row mt-3">
                        <span class="risk-label ${isSafe ? 'risk-low' : 'risk-high'}">${isSafe ? 'Safe' : 'Phishing'}</span>
                        <span class="risk-value">Confidence: ${confidence}</span>
                    </div>
                </div>
            </div>
            <div class="text-center mt-4">
                <button class="btn btn-outline-light btn-lg check-another-btn" type="button" onclick="resetUrlChecker()">
                    <i class="fas fa-search me-2"></i>Check Another Input
                </button>
            </div>
        </div>
    `;

    result.style.display = 'block';
    playSound(isSafe ? 'success' : 'warning');
}

// Enhanced check button event handler
async function handleUrlCheck() {
    const url = urlInput.value.trim();
    if (!url) {
        showToast('Please enter a URL to check', 'warning');
        urlInput.focus();
        return;
    }

    // Basic URL validation
    if (!isValidUrl(url)) {
        showToast('Please enter a valid URL', 'error');
        urlInput.focus();
        return;
    }

    // Disable button during processing
    checkButton.disabled = true;
    checkButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';

    showLoading();

    try {
        const response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url })
        });

        const data = await response.json();

        if (!response.ok || data.error) {
            showError(data.error || 'Error analyzing URL');
            return;
        }

        showResult(data);
    } catch (error) {
        showError('Error connecting to server. Please check your internet connection and try again.');
        console.error('Error:', error);
    } finally {
        // Re-enable button
        checkButton.disabled = false;
        checkButton.innerHTML = '<i class="fas fa-shield-alt me-2"></i>Check Now';
    }
}

async function handleQrCheck() {
    if (!qrImageInput || !checkQrButton) {
        showToast('QR scanner controls are not available right now.', 'error');
        return;
    }

    const file = qrImageInput.files && qrImageInput.files[0] ? qrImageInput.files[0] : null;
    if (!file) {
        showToast('Please upload a QR image first.', 'warning');
        qrImageInput.focus();
        return;
    }

    const fileName = (file.name || '').toLowerCase();
    const allowedExt = ['.png', '.jpg', '.jpeg'];
    const allowedMime = ['image/png', 'image/jpeg'];
    const extOk = allowedExt.some((ext) => fileName.endsWith(ext));
    const mimeOk = allowedMime.includes((file.type || '').toLowerCase());

    if (!(extOk || mimeOk)) {
        showToast('Invalid image type. Upload PNG or JPG image.', 'error');
        return;
    }

    checkQrButton.disabled = true;
    checkQrButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning...';

    showQrLoading(file.name);

    try {
        const formData = new FormData();
        formData.append('qr_image', file);

        const response = await fetch('/predict-qr', {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok || data.error) {
            showError(data.error || 'Error analyzing QR image');
            return;
        }

        showResult(data);
        if (data.decoded_url) {
            showToast(`Extracted URL: ${data.decoded_url}`, 'info');
        }
    } catch (error) {
        showError('Error connecting to server. Please try again with another image.');
        console.error('QR Error:', error);
    } finally {
        checkQrButton.disabled = false;
        checkQrButton.innerHTML = '<i class="fas fa-qrcode me-2"></i>Scan QR';
    }
}

async function handleEmailCheck() {
    if (!emailInput || !checkEmailButton) {
        showToast('Email checker controls are not available right now.', 'error');
        return;
    }

    const text = emailInput.value.trim();
    if (!text) {
        showToast('Please paste email content first.', 'warning');
        emailInput.focus();
        return;
    }

    checkEmailButton.disabled = true;
    checkEmailButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
    showLoading();

    try {
        const response = await fetch('/predict_email', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email: text })
        });

        const data = await response.json();
        if (!response.ok || data.error) {
            showError(data.error || 'Error analyzing email text');
            return;
        }

        showEmailResult(data);
    } catch (error) {
        showError('Error connecting to server. Please try again.');
        console.error('Email Error:', error);
    } finally {
        checkEmailButton.disabled = false;
        checkEmailButton.innerHTML = '<i class="fas fa-shield-alt me-2"></i>Check Email';
    }
}

async function handleSmsCheck() {
    if (!smsInput || !checkSmsButton) {
        showToast('SMS checker controls are not available right now.', 'error');
        return;
    }

    const text = smsInput.value.trim();
    if (!text) {
        showToast('Please paste SMS content first.', 'warning');
        smsInput.focus();
        return;
    }

    checkSmsButton.disabled = true;
    checkSmsButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
    showLoading();

    try {
        const response = await fetch('/predict/sms', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ text })
        });

        const data = await response.json();
        if (!response.ok || data.error) {
            showError(data.error || 'Error analyzing SMS text');
            return;
        }

        showSmsResult(data, text.slice(0, 260));
    } catch (error) {
        showError('Error connecting to server. Please try again.');
        console.error('SMS Error:', error);
    } finally {
        checkSmsButton.disabled = false;
        checkSmsButton.innerHTML = '<i class="fas fa-shield-alt me-2"></i>Check SMS';
    }
}

// URL validation function
function isValidUrl(string) {
    try {
        // Handle various URL formats
        let urlToTest = string.trim();
        
        // Add protocol if missing
        if (!urlToTest.startsWith('http://') && !urlToTest.startsWith('https://')) {
            urlToTest = 'https://' + urlToTest;
        }
        
        const url = new URL(urlToTest);
        
        // Check for valid protocols
        if (!['http:', 'https:'].includes(url.protocol)) {
            return false;
        }
        
        // Check for valid hostname
        if (!url.hostname || url.hostname.length === 0) {
            return false;
        }
        
        // Allow localhost and IP addresses
        if (url.hostname === 'localhost' || url.hostname === '127.0.0.1') {
            return true;
        }
        
        // Allow IP addresses
        const ipRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (ipRegex.test(url.hostname)) {
            return true;
        }
        
        // Check for basic domain format
        const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        return domainRegex.test(url.hostname);
        
    } catch (error) {
        return false;
    }
}

// Enhanced particle effect for hero section
function createParticles() {
    const particles = document.querySelector('.hero-particles');
    if (particles) {
        particles.innerHTML = '';
    }
}

// Intersection Observer for animations
const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
};

const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
        if (entry.isIntersecting) {
            entry.target.style.animationPlayState = 'running';
            
            // Add stagger effect for multiple elements
            const children = entry.target.querySelectorAll('.fade-in-up, .slide-in-left');
            children.forEach((child, index) => {
                child.style.animationDelay = `${index * 0.1}s`;
            });
        }
    });
});

// Observe elements for animations
document.addEventListener('DOMContentLoaded', () => {
    const animatedElements = document.querySelectorAll('.fade-in-up, .slide-in-left, .feature-card, .examples-card');
    animatedElements.forEach(el => {
        observer.observe(el);
    });
});

// Contact form handling with validation
const contactForm = document.getElementById('contactForm');
if (contactForm) {
    contactForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const nameInput = contactForm.querySelector('input[name="name"]');
        const emailInputField = contactForm.querySelector('input[name="email"]');
        const messageInput = contactForm.querySelector('textarea[name="message"]');

        const payload = {
            name: (nameInput?.value || '').trim(),
            email: (emailInputField?.value || '').trim(),
            message: (messageInput?.value || '').trim()
        };

        if (!payload.name || !payload.email || !payload.message) {
            showToast('Please fill in all contact form fields.', 'warning');
            return;
        }

        if (!isValidEmail(payload.email)) {
            showToast('Please enter a valid email address.', 'warning');
            return;
        }

        const submitBtn = contactForm.querySelector('button[type="submit"]');
        const originalText = submitBtn.innerHTML;

        // Disable submit button
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Sending...';

        try {
            const response = await fetch('/contact/send', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(payload)
            });

            const data = await response.json();
            if (!response.ok || data.error) {
                showToast(data.error || 'Failed to send message. Please try again.', 'error');
                return;
            }

            showToast(data.message || 'Message sent successfully! We\'ll get back to you soon.', 'success');
            contactForm.reset();
        } catch (error) {
            showToast('Failed to send message. Please try again.', 'error');
            console.error('Contact form error:', error);
        } finally {
            // Re-enable submit button
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    });
}

// Newsletter form handling
const newsletterForm = document.querySelector('.newsletter-form');
if (newsletterForm) {
    newsletterForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const email = newsletterForm.querySelector('input[type="email"]').value;
        if (!isValidEmail(email)) {
            showToast('Please enter a valid email address', 'warning');
            return;
        }
        
        const submitBtn = newsletterForm.querySelector('button');
        const originalText = submitBtn.innerHTML;
        
        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
        
        try {
            // Simulate newsletter subscription
            await new Promise(resolve => setTimeout(resolve, 1500));
            
            showToast('Successfully subscribed to newsletter!', 'success');
            newsletterForm.reset();
        } catch (error) {
            showToast('Subscription failed. Please try again.', 'error');
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    });
}

// Email validation
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Footer policy content toggles
const policyDisplay = document.getElementById('policyDisplay');
const policyTriggers = document.querySelectorAll('.policy-trigger');

const POLICY_CONTENT = {
    privacy: {
        title: 'Privacy Policy',
        body: 'We collect only the information needed to support your requests and improve platform security. We do not sell personal data and process submissions with confidentiality and reasonable safeguards.'
    },
    terms: {
        title: 'Terms of Service',
        body: 'By using ThreatSpectra, you agree to lawful and responsible use. Detection outputs are advisory insights and should be combined with independent validation before taking critical decisions.'
    },
    cookie: {
        title: 'Cookie Policy',
        body: 'We use essential cookies for core functionality and limited analytics to improve reliability and user experience. Cookies are not used to sell personal data.'
    }
};

if (policyDisplay && policyTriggers.length) {
    const renderPolicy = (policyKey) => {
        const selected = POLICY_CONTENT[policyKey];
        if (!selected) return;

        policyDisplay.innerHTML = `
            <h6 class="policy-title">${selected.title}</h6>
            <p class="policy-body">${selected.body}</p>
        `;

        policyTriggers.forEach((trigger) => {
            trigger.classList.toggle('active', trigger.dataset.policy === policyKey);
        });
    };

    policyTriggers.forEach((trigger) => {
        trigger.addEventListener('click', (event) => {
            event.preventDefault();
            renderPolicy(trigger.dataset.policy);
        });
    });
}

// Enhanced toast notification system
function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    const icons = {
        success: 'fas fa-check-circle',
        error: 'fas fa-exclamation-circle',
        warning: 'fas fa-exclamation-triangle',
        info: 'fas fa-info-circle'
    };
    
    toast.innerHTML = `
        <i class="${icons[type]} me-2"></i>
        <span>${message}</span>
        <button class="toast-close" onclick="this.parentElement.remove()">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    document.body.appendChild(toast);

    // Show toast
    requestAnimationFrame(() => {
        toast.classList.add('show');
    });

    // Auto remove after 5 seconds
    setTimeout(() => {
        if (toast.parentElement) {
            toast.classList.remove('show');
            setTimeout(() => {
                if (toast.parentElement) {
                    toast.remove();
                }
            }, 300);
        }
    }, 5000);
}

// Sound effects (optional - requires audio files)
function playSound(type) {
    // Uncomment and add audio files for sound effects
    /*
    const audio = new Audio(`/static/sounds/${type}.mp3`);
    audio.volume = 0.3;
    audio.play().catch(e => console.log('Sound play failed:', e));
    */
}

// Parallax effect for hero section
window.addEventListener('scroll', () => {
    const scrolled = window.pageYOffset;
    const parallax = document.querySelector('.hero-section');
    const rate = scrolled * -0.5;
    
    if (parallax) {
        parallax.style.transform = `translateY(${rate}px)`;
    }
});

// Particle effects disabled for clean cyber-grid background.

// Debounce function for performance
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Add loading state for page transitions
window.addEventListener('beforeunload', () => {
    document.body.classList.add('page-loading');
});

// Remove loading state when page loads
window.addEventListener('load', () => {
    document.body.classList.remove('page-loading');
    
    // Trigger any delayed animations
    setTimeout(() => {
        document.body.classList.add('page-loaded');
    }, 100);
    
    createParticles();
});

// Backup particle creation function
function createBackupParticle(container) {
    const particle = document.createElement('div');
    particle.style.cssText = `
        position: absolute;
        width: 4px;
        height: 4px;
        background: radial-gradient(circle, rgba(0, 255, 255, 0.8), rgba(102, 126, 234, 0.4));
        border-radius: 50%;
        left: ${Math.random() * 100}%;
        top: 100%;
        z-index: 1;
        box-shadow: 0 0 10px rgba(0, 255, 255, 0.6);
        animation: floatUp ${15 + Math.random() * 10}s linear infinite;
        animation-delay: ${Math.random() * 2}s;
    `;
    
    container.appendChild(particle);
    console.log('Backup particle created');
    
    // Remove after animation
    setTimeout(() => {
        if (particle.parentNode) {
            particle.remove();
        }
    }, 30000);
}

// Create visible test particles immediately
function createTestParticles(container) {
    for (let i = 0; i < 5; i++) {
        const testParticle = document.createElement('div');
        testParticle.className = 'particle';
        testParticle.style.cssText = `
            width: 8px;
            height: 8px;
            left: ${20 + i * 15}%;
            background: radial-gradient(circle, rgba(0, 255, 255, 0.9), rgba(102, 126, 234, 0.6));
            box-shadow: 0 0 15px rgba(0, 255, 255, 0.8);
            animation: particleFloat3D 10s linear infinite;
            animation-delay: ${i * 0.5}s;
            z-index: 10;
            border: 1px solid rgba(0, 255, 255, 0.3);
        `;
        container.appendChild(testParticle);
        console.log('Test particle created at position', 20 + i * 15 + '%');
    }
}

// Simple and reliable particle system
function createSimpleParticles() {
    const heroSection = document.querySelector('.hero-section');
    if (!heroSection) {
        console.log('Hero section not found');
        return;
    }
    
    // Create particle container if it doesn't exist
    let particleContainer = document.querySelector('.hero-particles');
    if (!particleContainer) {
        particleContainer = document.createElement('div');
        particleContainer.className = 'hero-particles';
        heroSection.appendChild(particleContainer);
    }
    
    console.log('Creating simple particles...');
    
    // Function to create a single particle
    function createSingleParticle() {
        const particle = document.createElement('div');
        particle.style.cssText = `
            position: absolute;
            width: 4px;
            height: 4px;
            background: radial-gradient(circle, rgba(0, 255, 255, 0.8), rgba(102, 126, 234, 0.4));
            border-radius: 50%;
            left: ${Math.random() * 100}%;
            top: 100%;
            z-index: 1;
            box-shadow: 0 0 10px rgba(0, 255, 255, 0.6);
            animation: floatUp ${15 + Math.random() * 10}s linear infinite;
            animation-delay: ${Math.random() * 5}s;
        `;
        
        particleContainer.appendChild(particle);
        
        // Remove particle after animation completes and create a new one
        setTimeout(() => {
            if (particle.parentNode) {
                particle.remove();
            }
            // Create a new particle to replace this one
            createSingleParticle();
        }, 30000); // 30 seconds to ensure animation completes
    }
    
    // Create initial batch of 20 particles
    for (let i = 0; i < 20; i++) {
        setTimeout(() => {
            createSingleParticle();
            console.log(`Particle ${i + 1} created`);
        }, i * 200);
    }
    
    // Also create particles continuously every 5 seconds
    setInterval(() => {
        createSingleParticle();
        console.log('New particle created via interval');
    }, 5000);
}

console.log('🛡️ ThreatSpectra Enhanced - Ready to protect!');

import re
import urllib.parse
import tldextract
from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS

app = Flask(__name__)
# Restrict CORS to local development environment
CORS(app, resources={r"/api/*": {"origins": ["http://127.0.0.1:5000", "http://localhost:5000"]}})

# Prevent browser caching of static/template files during development
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return response

extractor = tldextract.TLDExtract(include_psl_private_domains=True)

# ==============================================================================
# CONFIGURATION & CONSTANTS
# ==============================================================================

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", 
    "is.gd", "rb.gy", "buff.ly", "rebrand.ly", "cutt.ly"
}

ENTERPRISE_TRUSTED_ROOTS = {
    "google.com", "github.com", "microsoft.com", "live.com", "office.com",
    "microsoftonline.com", "apple.com", "amazon.com", "paypal.com", "chase.com", 
    "wellsfargo.com", "hubspot.com", "medium.com", "zoom.us", "techdaily.io", 
    "example.com", "mit.edu"
}

TRUSTED_EXACT_HOSTS = {
    "accounts.google.com",
    "aws.amazon.com",
    "login.microsoftonline.com",
    "appleid.apple.com"
}

SHARED_CONTENT_HOSTS = {
    "raw.githubusercontent.com",
    "docs.google.com",
    "drive.google.com",
    "storage.googleapis.com",
    "s3.amazonaws.com"
}

BRAND_KEYWORDS = [
    "paypal", "paypa1", "google", "microsoft", "apple", 
    "amazon", "netflix", "chase", "wellsfargo", "bankofamerica", "dropbox"
]

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".club", ".work", ".info", ".kim", ".gq", ".cf", 
    ".cc", ".zip", ".mov", ".site", ".tech", ".online", ".download"
}

SUSPICIOUS_DOMAIN_PATTERNS = [
    "security-check", "verify", "update", "support", 
    "portal", "renew", "subscription", "file-share"
]

MESSAGES_DB = {
    1: {
        "id": 1,
        "sender": "security-alert@verify-account-update.com",
        "subject": "Urgent: Account Suspended",
        "body": "Dear user, your account requires immediate verification. Please visit https://amazon-security-check.xyz/login?session=encoded%20string%21&user=verify%40test.com to fix this.",
        "urls": ["https://amazon-security-check.xyz/login?session=encoded%20string%21&user=verify%40test.com"],
        "context_module": {
            "urgency_score": 100,
            "has_urgency_language": True,
            "detected_urgency_phrases": ["urgent", "suspended", "immediate", "verify"],
            "suspicious_sender_domain": True
        }
    },
    2: {
        "id": 2,
        "sender": "newsletter@techdaily.io",
        "subject": "Weekly Tech Digest",
        "body": "Check out the new trends at https://techdaily.io/news and view our updates here https://bit.ly/3xXyZ1 or read our blog http://subdomain.example-blog.org/article?id=998&ref=tracking",
        "urls": [
            "https://techdaily.io/news", 
            "https://bit.ly/3xXyZ1", 
            "http://subdomain.example-blog.org/article?id=998&ref=tracking"
        ],
        "context_module": {
            "urgency_score": 0,
            "has_urgency_language": False,
            "detected_urgency_phrases": [],
            "suspicious_sender_domain": False
        }
    },
    3: {
        "id": 3,
        "sender": "info@company.com",
        "subject": "Internal Company Update",
        "body": "Hello team, please remember that the office will remain closed this coming Friday. No action is required.",
        "urls": [],
        "context_module": {
            "urgency_score": 0,
            "has_urgency_language": False,
            "detected_urgency_phrases": [],
            "suspicious_sender_domain": False
        }
    }
}

# ==============================================================================
# eTLD+1 EXTRACTION & TRUST ENGINE
# ==============================================================================

def extract_domain_components(raw_url: str) -> dict:
    url_to_parse = raw_url.strip()
    if not url_to_parse.startswith(("http://", "https://")):
        url_to_parse = "http://" + url_to_parse

    extracted = extractor(url_to_parse)
    registered_domain = extracted.registered_domain.lower() if extracted.registered_domain else ""
    subdomain = extracted.subdomain.lower() if extracted.subdomain else ""
    fqdn = extracted.fqdn.lower() if extracted.fqdn else ""

    return {
        "fqdn": fqdn,
        "registered_domain": registered_domain,
        "subdomain": subdomain,
        "suffix": extracted.suffix.lower() if extracted.suffix else ""
    }


def evaluate_domain_trust(components: dict) -> bool:
    fqdn = components["fqdn"]
    reg_domain = components["registered_domain"]

    if fqdn in SHARED_CONTENT_HOSTS:
        return False

    if fqdn in TRUSTED_EXACT_HOSTS:
        return True
        
    if reg_domain in ENTERPRISE_TRUSTED_ROOTS:
        return True

    return False

# ==============================================================================
# RE-WEIGHTED HEURISTIC ANALYSIS ENGINE
# ==============================================================================

def analyze_url_heuristics(url, email_context=None):
    if email_context is None:
        email_context = {}

    score = 0
    reasons = []
    contributions = []

    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "http://" + raw_url

    parsed = urllib.parse.urlparse(raw_url)
    full_url_lower = raw_url.lower()

    components = extract_domain_components(raw_url)
    fqdn = components["fqdn"]
    subdomain = components["subdomain"]
    
    is_trusted = evaluate_domain_trust(components)

    # Exemption Check for core trusted enterprise roots (if not shortener or shared content host)
    if is_trusted and fqdn not in KNOWN_SHORTENERS and fqdn not in SHARED_CONTENT_HOSTS:
        return {
            "target_url": url,
            "url": url,
            "etld_plus_one": components["registered_domain"],
            "subdomain": components["subdomain"],
            "risk_score": 0,
            "max_possible_score": 100,
            "classification": "LOW",
            "risk_label": "CLEAN / LOW RISK",
            "recommendation": "OPEN",
            "score_contributions": [],
            "explainable_reasons": []
        }

    # Percent-Encoding in Hostname Check (+60 Penalty)
    raw_netloc = parsed.netloc.split('@')[-1].split(':')[0]
    if "%" in raw_netloc:
        score += 60
        contributions.append({"category": "Hostname Encoding Masking", "score": 60, "max": 100})
        reasons.append("Hostname contains percent-encoded characters used to obfuscate domain identity.")

    # Rule 1: Raw IP Host Check (+40 Base, +80 if targeting credential/brand paths)
    ip_host = raw_netloc.split(':')[0]
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, ip_host):
        has_brand_path = any(brand in parsed.path.lower() for brand in BRAND_KEYWORDS)
        has_action_path = any(kw in parsed.path.lower() for kw in ["login", "verify", "account", "signin", "admin"])
        
        if has_brand_path or has_action_path:
            ip_score = 80
            reason_msg = "Raw IP address hosting explicit brand or credential target path."
        else:
            ip_score = 40
            reason_msg = "URL uses a raw IP address instead of a domain name."
            
        score += ip_score
        contributions.append({"category": "Raw IP Address Risk", "score": ip_score, "max": 100})
        reasons.append(reason_msg)

    # Rule 2: URL Shortener Check (+35)
    if fqdn in KNOWN_SHORTENERS or any(s in fqdn for s in KNOWN_SHORTENERS):
        score += 35
        contributions.append({"category": "URL Shortener / Masking", "score": 35, "max": 100})
        reasons.append("URL utilizes a known shortening service that masks the real destination.")

    # Rule 3: Shared Content Platform Payload Inspection
    if fqdn in SHARED_CONTENT_HOSTS:
        path_lower = parsed.path.lower()
        query_lower = parsed.query.lower()

        credential_keywords = ["login", "signin", "verify", "billing", "account", "update", "authorize", "session", "password"]
        unsafe_extensions = [".html", ".htm", ".exe", ".scr", ".bat", ".ps1", ".vbs", ".php"]

        has_cred_keywords = any(kw in path_lower or kw in query_lower for kw in credential_keywords)
        has_unsafe_ext = any(path_lower.endswith(ext) for ext in unsafe_extensions)

        if has_cred_keywords or has_unsafe_ext:
            score += 100
            contributions.append({"category": "Payload Risk on Shared Infrastructure", "score": 100, "max": 100})
            reasons.append(f"Public content platform ({fqdn}) hosts explicit credential targets or executable payloads.")

    # Rules 4-8: General Domain Heuristics for Untrusted Roots
    if not is_trusted and fqdn not in SHARED_CONTENT_HOSTS:
        # Rule 4: Normalized Brand Impersonation Check
        normalized_fqdn = re.sub(r'[^a-z]', '', fqdn)
        
        for brand in BRAND_KEYWORDS:
            normalized_brand = re.sub(r'[^a-z]', '', brand)
            if brand in fqdn or normalized_brand in normalized_fqdn:
                if "-" in fqdn or any(char.isdigit() for char in fqdn):
                    brand_score = 75
                    reason_msg = f"Domain uses high-risk lexical squatting / obfuscated brand impersonation ('{brand}')."
                else:
                    brand_score = 45
                    reason_msg = f"Domain impersonates legitimate brand '{brand}'."
                
                score += brand_score
                contributions.append({"category": "Brand Impersonation", "score": brand_score, "max": 100})
                reasons.append(reason_msg)
                break

        # Rule 5: Suspicious TLD / Domain Pattern (+25)
        has_suspicious_tld = any(fqdn.endswith(tld) for tld in SUSPICIOUS_TLDS)
        has_suspicious_pattern = any(p in fqdn for p in SUSPICIOUS_DOMAIN_PATTERNS)

        if has_suspicious_tld or has_suspicious_pattern:
            score += 25
            contributions.append({"category": "Suspicious TLD / Domain Pattern", "score": 25, "max": 100})
            reasons.append("Domain utilizes a high-risk TLD or suspicious keyword pattern.")

        # Rule 6: Sensitive Action Keywords (+20)
        sensitive_keywords = ["login", "signin", "verify", "billing", "account", "update", "authorize", "session"]
        if any(kw in full_url_lower for kw in sensitive_keywords):
            score += 20
            contributions.append({"category": "Credential / Action Indicators", "score": 20, "max": 100})
            reasons.append("URL contains sensitive action or credential harvesting keywords.")

        # Rule 7: Deep Subdomain Hierarchy (+15)
        subdomain_parts = [p for p in subdomain.split('.') if p and p != "www"]
        if len(subdomain_parts) >= 2:
            score += 15
            contributions.append({"category": "Deep Subdomain Hierarchy", "score": 15, "max": 100})
            reasons.append(f"Domain uses deep subdomain layering ({len(subdomain_parts)} sub-levels) on untrusted root.")

        # Rule 8: Insecure HTTP (+20)
        if parsed.scheme == "http" and not re.match(ip_pattern, ip_host):
            score += 20
            contributions.append({"category": "Insecure HTTP Protocol", "score": 20, "max": 100})
            reasons.append("URL uses unencrypted HTTP communication.")

    # Rule 9: Context Addon (+15 Modifier)
    if email_context.get('has_urgency_language') or email_context.get('suspicious_sender_domain'):
        score += 15
        contributions.append({"category": "Context Indicators", "score": 15, "max": 100})
        reasons.append("Email context exhibits high-urgency or sender domain anomalies.")

    final_score = min(100, max(0, score))

    if final_score >= 50:
        classification, risk_label, recommendation = "HIGH", "HIGH RISK PHISHING THREAT", "DO NOT OPEN"
    elif final_score >= 20:
        classification, risk_label, recommendation = "MEDIUM", "SUSPICIOUS LINK DETECTED", "BE CAREFUL"
    else:
        classification, risk_label, recommendation = "LOW", "CLEAN / LOW RISK", "OPEN"

    return {
        "target_url": url,
        "url": url,
        "etld_plus_one": components["registered_domain"],
        "subdomain": components["subdomain"],
        "risk_score": final_score,
        "max_possible_score": 100,
        "classification": classification,
        "risk_label": risk_label,
        "recommendation": recommendation,
        "score_contributions": contributions,
        "explainable_reasons": reasons
    }

# ==============================================================================
# DASHBOARD TEMPLATE HTML (UPGRADED TO MODERN EMAIL CLIENT UI)
# ==============================================================================

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pre-Click Phishing Detection Engine</title>
    <style>
        :root {
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-blue: #38bdf8;
            --danger-red: #ef4444;
            --warning-amber: #f59e0b;
            --safe-green: #10b981;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        body { background-color: var(--bg-color); color: var(--text-main); padding: 1.5rem; min-height: 100vh; }
        .header { margin-bottom: 1.5rem; border-bottom: 1px solid var(--border-color); padding-bottom: 0.75rem; }
        .header h1 { font-size: 1.5rem; display: flex; align-items: center; gap: 10px; }
        .subtitle { color: var(--text-muted); margin-top: 4px; font-size: 0.88rem; }
        
        .dashboard-grid { display: grid; grid-template-columns: 1fr 1.3fr 1.6fr; gap: 1rem; align-items: start; }
        .card { background-color: var(--card-bg); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem; min-height: 600px; display: flex; flex-direction: column; }
        h2 { font-size: 1.05rem; color: var(--accent-blue); border-bottom: 1px solid var(--border-color); padding-bottom: 0.6rem; margin-bottom: 1rem; }
        .placeholder { color: var(--text-muted); font-style: italic; font-size: 0.88rem; }

        /* Inbox Panel */
        .inbox-container { display: flex; flex-direction: column; gap: 8px; }
        .message-item { display: flex; align-items: center; gap: 12px; padding: 10px 12px; background: rgba(15, 23, 42, 0.6); border: 1px solid var(--border-color); border-radius: 6px; cursor: pointer; transition: all 0.2s ease; }
        .message-item:hover { background: #334155; border-color: var(--accent-blue); }
        .message-item.active { border-left: 4px solid var(--accent-blue); background: #24334a; }
        .avatar { width: 36px; height: 36px; border-radius: 50%; background: #3b82f6; color: #ffffff; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.9rem; flex-shrink: 0; }
        .msg-details { flex-grow: 1; overflow: hidden; }
        .sender { font-weight: 600; font-size: 0.85rem; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .subject { font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

        /* Realistic Email Viewer Panel */
        .email-card { background: rgba(15, 23, 42, 0.5); border: 1px solid var(--border-color); border-radius: 8px; padding: 1.25rem; display: flex; flex-direction: column; gap: 1rem; flex-grow: 1; }
        .email-header-meta { border-bottom: 1px solid var(--border-color); padding-bottom: 12px; }
        .email-subject-title { font-size: 1.15rem; font-weight: 700; color: var(--text-main); margin-bottom: 10px; }
        .sender-row { display: flex; align-items: center; gap: 12px; }
        .sender-info-text { display: flex; flex-direction: column; }
        .sender-name-label { font-size: 0.88rem; font-weight: 600; color: var(--text-main); }
        .sender-email-label { font-size: 0.78rem; color: var(--text-muted); }
        .email-body-content { font-size: 0.9rem; line-height: 1.6; color: var(--text-main); white-space: pre-wrap; word-break: break-word; padding: 8px 0; }
        
        .context-pill-bar { display: flex; flex-wrap: wrap; gap: 8px; padding-top: 12px; border-top: 1px dashed var(--border-color); font-size: 0.75rem; margin-top: auto; }
        .context-pill { background: var(--bg-color); border: 1px solid var(--border-color); padding: 4px 8px; border-radius: 4px; color: var(--text-muted); }
        .context-pill strong { color: var(--text-main); }

        /* Risk Inspector Panel */
        .risk-card { background: rgba(15, 23, 42, 0.7); border: 1px solid var(--border-color); border-radius: 8px; padding: 1rem; margin-bottom: 1rem; }
        .url-box { background: #090d16; border: 1px solid var(--border-color); padding: 8px 10px; border-radius: 4px; font-family: monospace; font-size: 0.78rem; color: var(--accent-blue); word-break: break-all; margin-bottom: 10px; }
        .risk-header { display: flex; align-items: center; gap: 12px; margin-bottom: 10px; padding-bottom: 10px; border-bottom: 1px solid var(--border-color); }
        .score-badge { font-size: 1.5rem; font-weight: 800; padding: 6px 12px; border-radius: 6px; background: var(--bg-color); text-align: center; min-width: 95px; border: 2px solid; }
        
        .HIGH { color: var(--danger-red); border-color: var(--danger-red); }
        .MEDIUM { color: var(--warning-amber); border-color: var(--warning-amber); }
        .LOW { color: var(--safe-green); border-color: var(--safe-green); }

        .rec-banner { display: inline-block; margin-top: 4px; font-size: 0.75rem; font-weight: 700; padding: 2px 8px; border-radius: 4px; border: 1px solid; text-transform: uppercase; }
        .rec-banner.HIGH { background: rgba(239, 68, 68, 0.2); }
        .rec-banner.MEDIUM { background: rgba(245, 158, 11, 0.2); }
        .rec-banner.LOW { background: rgba(16, 185, 129, 0.2); }

        .section-title { font-size: 0.75rem; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; margin: 12px 0 6px 0; }
        .breakdown-row { display: flex; align-items: center; font-size: 0.8rem; margin-bottom: 4px; }
        .breakdown-label { width: 180px; color: var(--text-main); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
        .bar-track { flex-grow: 1; background: var(--bg-color); height: 8px; border-radius: 4px; margin: 0 8px; overflow: hidden; border: 1px solid var(--border-color); }
        .bar-fill { height: 100%; border-radius: 4px; }
        .bar-fill.HIGH { background: var(--danger-red); }
        .bar-fill.MEDIUM { background: var(--warning-amber); }
        .bar-fill.LOW { background: var(--safe-green); }

        .reasons-list { list-style: none; padding: 0; margin: 0; display: flex; flex-direction: column; gap: 4px; }
        .reasons-list li { font-size: 0.8rem; color: var(--text-main); background: rgba(15, 23, 42, 0.5); padding: 6px 10px; border-left: 3px solid var(--accent-blue); border-radius: 0 4px 4px 0; }

        .action-bar { display: flex; gap: 10px; margin-top: 12px; padding-top: 10px; border-top: 1px solid var(--border-color); }
        .btn { flex: 1; padding: 8px 12px; border: none; border-radius: 6px; font-weight: 700; font-size: 0.8rem; cursor: pointer; transition: all 0.2s ease; text-align: center; }
        .btn-cancel { background: #334155; color: var(--text-main); }
        .btn-cancel:hover { background: #475569; }
        .btn-proceed { background: var(--danger-red); color: white; }
        .btn-proceed.LOW { background: var(--safe-green); color: black; }

        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100vw; height: 100vh; background: rgba(15, 23, 42, 0.85); backdrop-filter: blur(4px); z-index: 999; justify-content: center; align-items: center; }
        .modal-overlay.active { display: flex; }
        .modal-card { background: var(--card-bg); border: 2px solid var(--border-color); width: 90%; max-width: 650px; border-radius: 10px; padding: 1.5rem; }
    </style>
</head>
<body>

    <header class="header">
        <h1>Pre-Click Phishing Detection Engine</h1>
        <p class="subtitle">Real-Time Contextual Analysis Dashboard</p>
    </header>

    <main class="dashboard-grid">
        <section class="card">
            <h2>Inbox</h2>
            <div id="inbox-list" class="inbox-container">
                {% for msg in messages %}
                <div class="message-item" onclick="handleOpenMessage({{ msg.id }}, this)">
                    <div class="avatar">{{ msg.sender[0].upper() }}</div>
                    <div class="msg-details">
                        <div class="sender">{{ msg.sender }}</div>
                        <div class="subject">{{ msg.subject }}</div>
                    </div>
                </div>
                {% endfor %}
            </div>
        </section>

        <section class="card" id="message-viewer">
            <h2>Message Viewer</h2>
            <p class="placeholder">Select a message to open it and trigger automatic pre-click detection.</p>
        </section>

        <section class="card" id="url-detector-output">
            <h2>Pre-Click Link Inspector & Explainability</h2>
            <p class="placeholder">Select an email to analyze embedded URLs.</p>
        </section>
    </main>

    <div class="modal-overlay" id="intercept-modal">
        <div class="modal-card" id="modal-card-content"></div>
    </div>

    <script>
        let currentAnalysisResults = [];

        async function handleOpenMessage(id, element) {
            document.querySelectorAll('.message-item').forEach(el => el.classList.remove('active'));
            if (element) element.classList.add('active');

            const viewer = document.getElementById('message-viewer');
            const urlOutput = document.getElementById('url-detector-output');

            viewer.innerHTML = '<h2>Message Viewer</h2><p class="placeholder">Opening message...</p>';
            urlOutput.innerHTML = '<h2>Pre-Click Link Inspector & Explainability</h2><p class="placeholder">Running automatic analysis...</p>';

            try {
                const response = await fetch('/api/messages/' + id + '/open', { method: 'POST' });
                const data = await response.json();
                currentAnalysisResults = data.analysis_results || [];
                const ctx = data.context_module || {};
                
                // Safe Body URL Rendering using structured HTML escape & string replacement
                let rawBody = data.body || '';
                let formattedBody = escapeHtml(rawBody);

                if (currentAnalysisResults.length > 0) {
                    currentAnalysisResults.forEach((res, index) => {
                        const targetUrl = res.target_url || res.url;
                        const escapedUrl = escapeHtml(targetUrl);
                        const linkTag = `<a href="#" data-url-index="${index}" onclick="triggerInterception(event, ${index})" style="color: var(--accent-blue); text-decoration: underline; font-weight: bold;">${escapedUrl}</a>`;
                        
                        formattedBody = formattedBody.split(escapedUrl).join(linkTag);
                    });
                }

                const initial = data.sender ? data.sender.charAt(0).toUpperCase() : '?';
                const urgencyPhrases = (ctx.detected_urgency_phrases && ctx.detected_urgency_phrases.length > 0) 
                    ? ctx.detected_urgency_phrases.map(escapeHtml).join(', ') 
                    : 'None';

                viewer.innerHTML = `
                    <h2>Message Viewer</h2>
                    <div class="email-card">
                        <div class="email-header-meta">
                            <h3 class="email-subject-title">${escapeHtml(data.subject)}</h3>
                            <div class="sender-row">
                                <div class="avatar">${initial}</div>
                                <div class="sender-info-text">
                                    <span class="sender-name-label">${escapeHtml(data.sender.split('@')[0])}</span>
                                    <span class="sender-email-label">From: ${escapeHtml(data.sender)}</span>
                                </div>
                            </div>
                        </div>

                        <div class="email-body-content">${formattedBody}</div>

                        <div class="context-pill-bar">
                            <span class="context-pill">Urgency Score: <strong>${ctx.urgency_score || 0}/100</strong></span>
                            <span class="context-pill">Urgency Words: <strong>${urgencyPhrases}</strong></span>
                            <span class="context-pill">Sender Domain: <strong style="color: ${ctx.suspicious_sender_domain ? 'var(--danger-red)' : 'var(--safe-green)'}">${ctx.suspicious_sender_domain ? 'SUSPICIOUS' : 'Standard'}</strong></span>
                        </div>
                    </div>
                `;

                urlOutput.innerHTML = '<h2>Pre-Click Link Inspector & Explainability</h2>';
                if (currentAnalysisResults.length > 0) {
                    currentAnalysisResults.forEach((res, idx) => {
                        urlOutput.appendChild(createRiskCard(res, idx, false));
                    });
                } else {
                    urlOutput.innerHTML += '<p class="placeholder" style="margin-top:12px;">No URLs detected in this message.</p>';
                }

            } catch (err) {
                viewer.innerHTML = '<h2>Message Viewer</h2><p class="placeholder" style="color: var(--danger-red);">Error loading message details.</p>';
            }
        }

        function createRiskCard(res, index, isModal) {
            isModal = !!isModal;
            const targetUrl = res.target_url || res.url;
            const score = res.risk_score || 0;
            const maxScore = res.max_possible_score || 100;
            const classification = res.classification || 'LOW';
            const riskLabel = res.risk_label || classification;
            const recText = res.recommendation || 'OPEN';
            const contributions = res.score_contributions || [];
            const reasons = res.explainable_reasons || [];

            const card = document.createElement('div');
            card.className = 'risk-card';

            let html = `
                <div style="color: var(--accent-blue); font-weight: bold; font-family: monospace; font-size: 0.8rem; margin-bottom: 6px;">[URL #${index + 1}]</div>
                <div class="url-box">${escapeHtml(targetUrl)}</div>

                <div class="risk-header">
                    <div class="score-badge ${classification}">${score}/${maxScore}</div>
                    <div>
                        <h3 class="${classification}" style="font-size: 0.95rem;">${escapeHtml(riskLabel)}</h3>
                        <span class="rec-banner ${classification}">Recommendation: ${escapeHtml(recText)}</span>
                    </div>
                </div>

                <h4 class="section-title">SCORE BREAKDOWN</h4>
                <div style="margin-bottom: 8px;">
            `;

            if (contributions.length === 0) {
                html += `<p class="placeholder">No penalty categories triggered (Base Score: 0/100).</p>`;
            } else {
                contributions.forEach(item => {
                    const val = item.score || 0;
                    const barWidth = Math.min(100, Math.max(10, val));
                    html += `
                        <div class="breakdown-row">
                            <span class="breakdown-label">${escapeHtml(item.category)}</span>
                            <div class="bar-track">
                                <div class="bar-fill ${classification}" style="width: ${barWidth}%;"></div>
                            </div>
                            <span style="font-weight: bold;" class="${classification}">+${val}</span>
                        </div>
                    `;
                });
            }
            html += `</div>`;

            html += `<h4 class="section-title">KEY RISK REASONS</h4><ul class="reasons-list">`;
            if (reasons.length === 0) {
                html += `<li>No threat indicators identified.</li>`;
            } else {
                reasons.forEach(r => { html += `<li>${escapeHtml(r)}</li>`; });
            }
            html += `</ul>`;

            const cancelHandler = isModal ? `cancelAndLock(${index})` : `stayOnDashboard(${index})`;
            html += `
                <div class="action-bar">
                    <button class="btn btn-cancel" onclick="${cancelHandler}">Stay Safe (Cancel)</button>
                    <button class="btn btn-proceed ${classification}" onclick="confirmOpenUrlByIndex(${index})">Proceed to Open Link</button>
                </div>
            `;

            card.innerHTML = html;
            return card;
        }

        function triggerInterception(event, index) {
            event.preventDefault();
            const res = currentAnalysisResults[index];
            if (!res) return;

            const modalOverlay = document.getElementById('intercept-modal');
            const modalContent = document.getElementById('modal-card-content');
            
            modalContent.innerHTML = '<h2 style="color: var(--accent-blue); margin-bottom: 1rem;">⚠️ Pre-Click Safety Interception</h2>';
            modalContent.appendChild(createRiskCard(res, index, true));
            modalOverlay.classList.add('active');
        }

        function closeModal() {
            document.getElementById('intercept-modal').classList.remove('active');
        }

        function cancelAndLock(index) {
            closeModal();
            stayOnDashboard(index);
        }

        function stayOnDashboard(index) {
            const links = document.querySelectorAll(`a[data-url-index="${index}"]`);
            links.forEach(link => {
                link.style.color = 'var(--text-muted)';
                link.style.textDecoration = 'line-through';
                link.onclick = function(e) {
                    e.preventDefault();
                    alert('This link was flagged as unsafe and canceled by the user.');
                };
            });
            alert('Decision Recorded: Remaining safely on dashboard. Link disabled.');
        }

        function confirmOpenUrlByIndex(index) {
            const res = currentAnalysisResults[index];
            if (!res) return;
            const targetUrl = res.target_url || res.url;
            
            if (confirm("Safety Notice:\\n\\nAre you sure you want to proceed to:\\n" + targetUrl)) {
                window.open(targetUrl, '_blank', 'noopener,noreferrer');
            }
            closeModal();
        }

        function escapeHtml(text) {
            if (!text) return '';
            return String(text).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
        }
    </script>
</body>
</html>
"""

# ==============================================================================
# FLASK ROUTE ENDPOINTS
# ==============================================================================

@app.route("/")
def serve_index():
    messages_list = list(MESSAGES_DB.values())
    return render_template_string(DASHBOARD_HTML, messages=messages_list)


@app.route("/api/analyze", methods=["POST"])
def analyze_single_url():
    data = request.get_json(silent=True) or {}
    url = data.get("url", "").strip()
    
    if not url:
        return jsonify({"error": "Invalid request payload. 'url' parameter is required."}), 400

    context = data.get("context", {})
    result = analyze_url_heuristics(url, email_context=context)
    return jsonify(result), 200


@app.route("/api/messages/<int:msg_id>/open", methods=["POST"])
def open_message(msg_id):
    msg = MESSAGES_DB.get(msg_id)
    if not msg:
        return jsonify({"error": "Message not found"}), 404

    ctx = msg.get("context_module", {})
    analysis_results = [analyze_url_heuristics(u, email_context=ctx) for u in msg.get("urls", [])]

    return jsonify({
        "id": msg["id"],
        "sender": msg["sender"],
        "subject": msg["subject"],
        "body": msg["body"],
        "context_module": ctx,
        "analysis_results": analysis_results
    }), 200


@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"status": "active", "engine": "heuristics_reweighted_final"}), 200


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
import os
import re
import requests
import json
from flask import Flask, request, render_template_string, jsonify
from PIL import Image
import pytesseract
from datetime import datetime

API_KEY = 'b4e729eb2f285e1907b8be8ed61fb86b3a5a5bcc3efacd58891a83b63280fa2f'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Store recent scans for dashboard
recent_scans = []

def scan_url(url):
    headers = {"x-apikey": API_KEY}
    data = {"url": url}
    response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)
    scan_id = response.json()["data"]["id"]
    result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
    return result.json()

def scan_file(file_path):
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as f:
        files = {"file": f}
        response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)
    scan_id = response.json()["data"]["id"]
    result = requests.get(f"https://www.virustotal.com/api/v3/analyses/{scan_id}", headers=headers)
    return result.json()

def extract_text_from_image(image_path):
    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        return text
    except Exception as e:
        return f"Error reading image: {e}"

def find_urls_domains_emails(text):
    url_pattern = r'https?://[^\s]+'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    email_pattern = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    urls = re.findall(url_pattern, text)
    domains = re.findall(domain_pattern, text)
    emails = re.findall(email_pattern, text)
    return set(urls), set(domains), set(emails)

def ai_phishing_score(url):
    # Simple ML-inspired heuristic: suspicious keywords, length, digits, symbols
    suspicious_keywords = ['login', 'secure', 'update', 'verify', 'account', 'bank', 'free', 'gift', 'password']
    score = 0
    url_lower = url.lower()
    for kw in suspicious_keywords:
        if kw in url_lower:
            score += 2
    if len(url) > 40:
        score += 1
    if re.search(r'\d', url):
        score += 1
    if re.search(r'[\W_]', url):
        score += 1
    return score

def format_url_summary(url_result, url=None):
    stats = url_result['data']['attributes']['stats']
    url = url or url_result['meta']['url_info']['url']
    results = url_result['data']['attributes']['results']

    malicious_engines = [engine for engine, result in results.items() if result['category'] == 'malicious']
    suspicious_engines = [engine for engine, result in results.items() if result['category'] == 'suspicious']
    fraud_engines = [engine for engine, result in results.items() if 'fraud' in result.get('result', '').lower()]

    ai_score = ai_phishing_score(url)

    # Build a consistent card-styled HTML result
    verdict = 'Safe'
    verdict_class = 'status-safe'
    if malicious_engines or suspicious_engines or fraud_engines or ai_score > 3:
        verdict = 'Risky / Potentially Malicious'
        verdict_class = 'status-risk'

    summary = f"<div class=\"card\">"
    summary += f"<div class=\"result-title\">Scan summary for: <span style=\"font-weight:600;color:#e6eef3;\">{url}</span></div>"
    summary += f"<div class=\"result-item\"><strong>Verdict:</strong> <span class=\"{verdict_class}\">{verdict}</span><br>"
    summary += f"<strong>AI score:</strong> {ai_score} &nbsp; <small style=\"color:var(--muted)\">(higher = more suspicious)</small><br>"
    summary += f"<strong>Detections:</strong> Malicious={stats['malicious']} | Suspicious={stats['suspicious']} | Harmless={stats['harmless']} | Undetected={stats['undetected']} | Timeout={stats['timeout']}<br></div>"

    if malicious_engines:
        summary += "<div class=\"result-item\"><strong>Malicious (engines):</strong><br>" + "<br>".join(f"- {engine}" for engine in malicious_engines) + "</div>"
    if suspicious_engines:
        summary += "<div class=\"result-item\"><strong>Suspicious (engines):</strong><br>" + "<br>".join(f"- {engine}" for engine in suspicious_engines) + "</div>"
    if fraud_engines:
        summary += "<div class=\"result-item\"><strong>Fraud indicators:</strong><br>" + "<br>".join(f"- {engine}" for engine in fraud_engines) + "</div>"

    summary += "</div>"
    return summary

def format_file_summary(file_result, filename):
    stats = file_result['data']['attributes']['stats']
    results = file_result['data']['attributes']['results']
    malicious_engines = [engine for engine, result in results.items() if result['category'] == 'malicious']
    suspicious_engines = [engine for engine, result in results.items() if result['category'] == 'suspicious']

    verdict = 'Safe'
    verdict_class = 'status-safe'
    if malicious_engines or suspicious_engines:
        verdict = 'Risky / Potentially Malicious'
        verdict_class = 'status-risk'

    summary = f"<div class=\"card\">"
    summary += f"<div class=\"result-title\">Attachment scan: <span style=\"font-weight:600;color:#e6eef3\">{filename}</span></div>"
    summary += f"<div class=\"result-item\"><strong>Verdict:</strong> <span class=\"{verdict_class}\">{verdict}</span><br>"
    summary += f"<strong>Detections:</strong> Malicious={stats['malicious']} | Suspicious={stats['suspicious']} | Harmless={stats['harmless']} | Undetected={stats['undetected']}<br></div>"

    if malicious_engines:
        summary += "<div class=\"result-item\"><strong>Malicious (engines):</strong><br>" + "<br>".join(f"- {engine}" for engine in malicious_engines) + "</div>"
    if suspicious_engines:
        summary += "<div class=\"result-item\"><strong>Suspicious (engines):</strong><br>" + "<br>".join(f"- {engine}" for engine in suspicious_engines) + "</div>"

    summary += "</div>"
    return summary

HTML = '''
<!doctype html>
<html lang="en">
<head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width,initial-scale=1">
        <title>GhostPhish - AI Phishing Detection</title>
        <style>
                :root{
                        --bg:#0b0f12;
                        --panel:#0f1720;
                        --muted:#9aa6b2;
                        --accent:#22d3ee;
                        --danger:#ff6b6b;
                        --card:#0b1220;
                }
                html,body{height:100%;}
                body {
                        background: radial-gradient(1200px 400px at 10% 10%, rgba(34,211,238,0.06), transparent),
                                                radial-gradient(900px 300px at 90% 90%, rgba(34,211,238,0.03), transparent),
                                                var(--bg);
                        margin: 0;
                        color: #e6eef3;
                        font-family: Inter, 'Segoe UI', Arial, sans-serif;
                        -webkit-font-smoothing:antialiased;
                        display:flex;align-items:center;justify-content:center;padding:40px;
                }
                .app {
                        width:100%;max-width:1100px;border-radius:14px;overflow:hidden;box-shadow:0 10px 40px rgba(2,6,23,0.8);background:linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
                        border:1px solid rgba(255,255,255,0.03);
                        display:grid;grid-template-columns:320px 1fr;gap:0;
                }
                .sidebar{background:linear-gradient(180deg, rgba(17,24,39,0.6), rgba(8,12,16,0.6));padding:28px;display:flex;flex-direction:column;align-items:center}
                .logo {width:160px;height:160px;display:flex;align-items:center;justify-content:center;border-radius:8px;overflow:hidden;margin-bottom:16px}
                .logo img{width:140px;height:auto;display:block}
                .brand{font-weight:700;color:var(--accent);letter-spacing:2px;margin-top:6px}
                .subtitle{color:var(--muted);font-size:13px;text-align:center;margin-top:8px}
                .nav{width:100%;margin-top:22px}
                .nav button{width:100%;text-align:left;padding:12px 14px;margin-bottom:8px;border-radius:8px;border:none;background:transparent;color:var(--muted);cursor:pointer;font-weight:600}
                .nav button.active{background:linear-gradient(90deg, rgba(34,211,238,0.06), rgba(34,211,238,0.02));color:var(--accent);box-shadow:inset 0 0 0 1px rgba(255,255,255,0.02)}

                .main{padding:28px}
                .controls{display:flex;gap:12px;align-items:center;margin-bottom:14px}
                input[type=text]{flex:1;padding:10px 12px;border-radius:8px;border:1px solid rgba(255,255,255,0.04);background:var(--panel);color:inherit}
                input[type=file]{color:var(--muted)}
                .btn{background:var(--accent);color:#001219;padding:10px 14px;border-radius:8px;border:none;cursor:pointer;font-weight:700}
                .btn.secondary{background:transparent;color:var(--accent);border:1px solid rgba(34,211,238,0.12)}

                .card{background:var(--card);padding:16px;border-radius:10px;border:1px solid rgba(255,255,255,0.03);box-shadow:0 6px 18px rgba(2,6,23,0.6)}
                .result-title{font-weight:700;margin-bottom:8px}
                .result-item{padding:10px;border-radius:8px;background:linear-gradient(180deg, rgba(255,255,255,0.01), transparent);margin-bottom:10px}
                .status-safe{color:#10b981;font-weight:700}
                .status-risk{color:var(--danger);font-weight:800}

                .recent-list{list-style:none;padding:0;margin:0}
                .recent-list li{padding:8px 0;border-bottom:1px dashed rgba(255,255,255,0.02);font-size:13px;color:var(--muted)}

                @media(max-width:900px){.app{grid-template-columns:1fr;}.sidebar{flex-direction:row;gap:12px;padding:14px}.logo{width:64px;height:64px}.main{padding:16px}}
        </style>
        <script>
        function setActive(name){
                document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('active'));
                const el=document.getElementById('nav-'+name); if(el) el.classList.add('active');
                document.querySelectorAll('.panel').forEach(p=>p.style.display='none');
                const p=document.getElementById('panel-'+name); if(p) p.style.display='block';
        }
        window.addEventListener('DOMContentLoaded',()=>setActive('url'));

        async function scanUrl(e){e.preventDefault();const url=document.getElementById('url-input').value;document.getElementById('url-result').innerHTML='Scanning...';
                try{const res=await fetch('/api/scan_url',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});const j=await res.json();document.getElementById('url-result').innerHTML=j.summary||('<div>'+j.error+'</div>');setActive('url');}catch(err){document.getElementById('url-result').innerText=err}
        }

        async function scanScreenshot(e){e.preventDefault();const fd=new FormData(document.getElementById('screenshot-form'));document.getElementById('screenshot-result').innerHTML='Scanning...';
                try{const res=await fetch('/scan_screenshot',{method:'POST',body:fd});const text=await res.text();document.getElementById('screenshot-result').innerHTML=text;setActive('screenshot');}catch(err){document.getElementById('screenshot-result').innerText=err}
        }

        async function scanAttachment(e){e.preventDefault();const fd=new FormData(document.getElementById('attachment-form'));document.getElementById('attachment-result').innerHTML='Scanning...';
                try{const res=await fetch('/scan_attachment',{method:'POST',body:fd});const text=await res.text();document.getElementById('attachment-result').innerHTML=text;setActive('attachment');}catch(err){document.getElementById('attachment-result').innerText=err}
        }
        </script>
</head>
<body>
    <div class="app">
        <aside class="sidebar">
            <div class="logo card">
                <img src="/static/ghostphish_logo.png" alt="logo">
            </div>
            <div class="brand">GHOSTPHISH</div>
            <div class="subtitle">AI phishing detection & alert</div>
            <nav class="nav">
                <button id="nav-url" onclick="setActive('url')" class="active">Scan URL</button>
                <button id="nav-screenshot" onclick="setActive('screenshot')">Scan Screenshot</button>
                <button id="nav-attachment" onclick="setActive('attachment')">Scan Attachment</button>
                <button id="nav-dashboard" onclick="setActive('dashboard')">Dashboard</button>
            </nav>
        </aside>
        <main class="main">
            <section id="panel-url" class="panel">
                <div class="card">
                    <div style="display:flex;gap:12px;align-items:center">
                        <form id="url-form" onsubmit="scanUrl(event)" style="flex:1;display:flex;gap:12px">
                            <input type="text" id="url-input" placeholder="https://example.com/phishing-link" />
                            <button class="btn" type="submit">Scan</button>
                        </form>
                        <button class="btn secondary" onclick="document.getElementById('url-input').value=window.location.href">Use current URL</button>
                    </div>
                    <div id="url-result" style="margin-top:14px" class="result-item"></div>
                </div>
            </section>

            <section id="panel-screenshot" class="panel" style="display:none;margin-top:14px">
                <div class="card">
                    <form id="screenshot-form" onsubmit="scanScreenshot(event)" enctype="multipart/form-data">
                        <div style="display:flex;gap:12px;align-items:center">
                            <input type="file" name="screenshot" accept="image/*">
                            <button class="btn" type="submit">Scan Screenshot</button>
                        </div>
                    </form>
                    <div id="screenshot-result" style="margin-top:14px"></div>
                </div>
            </section>

            <section id="panel-attachment" class="panel" style="display:none;margin-top:14px">
                <div class="card">
                    <form id="attachment-form" onsubmit="scanAttachment(event)" enctype="multipart/form-data">
                        <div style="display:flex;gap:12px;align-items:center">
                            <input type="file" name="attachment">
                            <button class="btn" type="submit">Scan Attachment</button>
                        </div>
                    </form>
                    <div id="attachment-result" style="margin-top:14px"></div>
                </div>
            </section>

            <section id="panel-dashboard" class="panel" style="display:none;margin-top:14px">
                <div class="card">
                    <h3 class="result-title">Recent Scans</h3>
                    {% if recent_scans %}
                        <ul class="recent-list">
                        {% for scan in recent_scans %}
                            <li><b>{{ scan['type'] }}</b> — {{ scan['target'] }} <span style="float:right;color:var(--muted)">{{ scan['time'] }}</span></li>
                        {% endfor %}
                        </ul>
                    {% else %}
                        <p class="result-item">No scans yet.</p>
                    {% endif %}
                </div>
            </section>
        </main>
    </div>
</body>
</html>
'''

@app.route('/', methods=['GET'])
def index():
    return render_template_string(HTML, result=None, active_tab='urlscan', recent_scans=recent_scans)

@app.route('/scan_url', methods=['POST'])
def scan_url_route():
    url = request.form.get('url')
    if not url:
        return render_template_string(HTML, result="No URL provided.", active_tab='urlscan', recent_scans=recent_scans)
    try:
        url_result = scan_url(url)
        summary = format_url_summary(url_result, url)
        recent_scans.insert(0, {
            'type': 'URL',
            'target': url,
            'status': url_result['data']['attributes']['status'],
            'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })
        recent_scans[:] = recent_scans[:10]
    except Exception as e:
        summary = f"Error scanning URL: {e}"
    return render_template_string(HTML, result=summary, active_tab='urlscan', recent_scans=recent_scans)

@app.route('/scan_screenshot', methods=['POST'])
def scan_screenshot():
    file = request.files.get('screenshot')
    if not file:
        result = "No screenshot uploaded."
    else:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        text = extract_text_from_image(filepath)
        urls, domains, emails = find_urls_domains_emails(text)
        result = "<b>Extracted URLs:</b><br>"
        if urls:
            for url in urls:
                result += f"{url}<br>"
                try:
                    url_result = scan_url(url)
                    result += format_url_summary(url_result, url)
                    recent_scans.insert(0, {
                        'type': 'Screenshot URL',
                        'target': url,
                        'status': url_result['data']['attributes']['status'],
                        'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    })
                    recent_scans[:] = recent_scans[:10]
                except Exception as e:
                    result += f"Error scanning {url}: {e}<br>"
        else:
            result += "<i>No URLs found.</i><br>"
        result += "<b>Extracted Domains:</b><br>"
        if domains:
            result += "<br>".join(domains) + "<br>"
        else:
            result += "<i>No domains found.</i><br>"
        result += "<b>Extracted Emails:</b><br>"
        if emails:
            result += "<br>".join(emails) + "<br>"
        else:
            result += "<i>No emails found.</i><br>"
        os.remove(filepath)
    # Only return result HTML for AJAX
    return f'<div class="result-box">{result}</div>'

@app.route('/scan_attachment', methods=['POST'])
def scan_attachment():
    file = request.files.get('attachment')
    if not file:
        summary = "No attachment uploaded."
    else:
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        try:
            file_result = scan_file(filepath)
            summary = format_file_summary(file_result, file.filename)
            recent_scans.insert(0, {
                'type': 'Attachment',
                'target': file.filename,
                'status': file_result['data']['attributes']['status'],
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            })
            recent_scans[:] = recent_scans[:10]
        except Exception as e:
            summary = f"Error scanning attachment: {e}"
        os.remove(filepath)
    # Only return result HTML for AJAX
    return f'<div class="result-box">{summary}</div>'

# API endpoints for browser extension/app integration
@app.route('/api/scan_url', methods=['POST'])
def api_scan_url():
    data = request.get_json(force=True)
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided.'}), 400
    try:
        url_result = scan_url(url)
        summary = format_url_summary(url_result, url)
        return jsonify({'summary': summary})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan_text', methods=['POST'])
def api_scan_text():
    data = request.get_json(force=True)
    text = data.get('text')
    if not text:
        return jsonify({'error': 'No text provided.'}), 400
    urls, domains, emails = find_urls_domains_emails(text)
    results = []
    for url in urls:
        try:
            url_result = scan_url(url)
            summary = format_url_summary(url_result, url)
            results.append({'url': url, 'summary': summary})
        except Exception as e:
            results.append({'url': url, 'error': str(e)})
    return jsonify({'results': results, 'domains': list(domains), 'emails': list(emails)})

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
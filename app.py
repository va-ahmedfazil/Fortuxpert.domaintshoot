from flask import Flask, render_template, request, jsonify
import dns.resolver
import requests
import os
import csv
from io import StringIO

app = Flask(__name__)

EMAIL_PROVIDERS = {
    "google": "Google Workspace",
    "outlook": "Microsoft 365",
    "zoho": "Zoho Mail",
    "yahoodns": "Yahoo Mail",
    "protection.outlook.com": "Microsoft 365",
    "spf.protection.outlook.com": "Microsoft 365",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "messagingengine.com": "Fastmail"
}

SERVICE_SIGNATURES = {
    "cloudflare": "Cloudflare",
    "wordpress": "WordPress",
    "github.io": "GitHub Pages",
    "shopify": "Shopify",
    "akamai": "Akamai",
    "firebaseapp.com": "Firebase Hosting",
    "herokuapp.com": "Heroku",
    "netlify": "Netlify",
    "wixdns": "Wix",
    "weebly": "Weebly",
    "squarespace": "Squarespace"
}

def get_dns_records(domain):
    records = {}
    for record_type in ['A', 'CNAME', 'MX', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, record_type, raise_on_no_answer=False)
            records[record_type] = [r.to_text() for r in answers]
        except:
            records[record_type] = []
    return records

def get_http_status(domain):
    try:
        resp = requests.get(f"http://{domain}", timeout=4)
        return resp.status_code, resp.headers, resp.text[:1000]
    except:
        return None, {}, ""

def detect_email_solution(mx_records, txt_records):
    identifiers = " ".join(mx_records + txt_records).lower()
    for key, provider in EMAIL_PROVIDERS.items():
        if key in identifiers:
            return provider
    return "Unknown"

def detect_services(records, headers):
    detected = set()
    dns_data = " ".join(sum(records.values(), [])).lower()
    header_data = " ".join([f"{k}:{v}" for k, v in headers.items()]).lower()
    all_data = dns_data + " " + header_data

    for key, service in SERVICE_SIGNATURES.items():
        if key in all_data:
            detected.add(service)
    return list(detected)

def scan_domain(domain):
    result = {
        "domain": domain,
        "dns": {},
        "status": "",
        "email_provider": "",
        "services": []
    }

    records = get_dns_records(domain)
    result["dns"] = records

    status, headers, body = get_http_status(domain)
    result["status"] = status if status else "Unreachable"

    result["email_provider"] = detect_email_solution(records.get("MX", []), records.get("TXT", []))
    result["services"] = detect_services(records, headers)

    return result

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/check", methods=["POST"])
def check():
    domains = request.json.get("domains", "")
    domain_list = [d.strip() for d in domains.splitlines() if d.strip()]
    results = [scan_domain(domain) for domain in domain_list]
    return jsonify(results)

@app.route("/export", methods=["POST"])
def export():
    data = request.json.get("data", [])
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(["Domain", "A", "CNAME", "MX", "TXT", "Status", "Email Provider", "Services"])
    for item in data:
        writer.writerow([
            item["domain"],
            "; ".join(item["dns"].get("A", [])),
            "; ".join(item["dns"].get("CNAME", [])),
            "; ".join(item["dns"].get("MX", [])),
            "; ".join(item["dns"].get("TXT", [])),
            item["status"],
            item["email_provider"],
            "; ".join(item["services"])
        ])
    output = si.getvalue()
    return output, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': 'attachment; filename="domain_scan_results.csv"'
    }

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)

from flask import Flask, request, jsonify, render_template
import socket
import dns.resolver
import whois
import ssl
import requests
import subprocess
import json
import idna
from OpenSSL import crypto

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/whois')
def whois_lookup():
    domain = request.args.get('domain')
    try:
        w = whois.whois(domain)
        return jsonify({k: str(v) for k, v in w.items()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/dns')
def dns_lookup():
    domain = request.args.get('domain')
    try:
        records = {}
        for record_type in ['A', 'MX', 'TXT', 'NS', 'CNAME']:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [r.to_text() for r in answers]
            except Exception:
                records[record_type] = []
        return jsonify(records)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/reverse-ip')
def reverse_ip():
    ip = request.args.get('ip')
    try:
        result = socket.gethostbyaddr(ip)
        return jsonify({'hostname': result[0], 'aliases': result[1], 'ip_addresses': result[2]})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/ssl-cert')
def ssl_cert():
    domain = request.args.get('domain')
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return jsonify(cert)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/email-health')
def email_health():
    domain = request.args.get('domain')
    try:
        spf = []
        dkim = []
        dmarc = []
        try:
            spf = [r.to_text() for r in dns.resolver.resolve(domain, 'TXT') if 'v=spf1' in r.to_text()]
        except: pass
        try:
            dmarc = [r.to_text() for r in dns.resolver.resolve('_dmarc.' + domain, 'TXT') if 'v=DMARC1' in r.to_text()]
        except: pass
        try:
            dkim = [r.to_text() for r in dns.resolver.resolve('default._domainkey.' + domain, 'TXT')]
        except: pass
        return jsonify({'SPF': spf, 'DKIM': dkim, 'DMARC': dmarc})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/dnssec')
def dnssec():
    domain = request.args.get('domain')
    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        return jsonify({'DNSSEC': [r.to_text() for r in answers]})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/blacklist')
def blacklist():
    domain = request.args.get('domain')
    return jsonify({'blacklist': 'Functionality to be implemented with 3rd party service'})

@app.route('/http-headers')
def http_headers():
    domain = request.args.get('domain')
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        return jsonify({'headers': dict(response.headers), 'redirects': [r.url for r in response.history]})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/cdn-fingerprint')
def cdn_fingerprint():
    domain = request.args.get('domain')
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        tech = {}
        if 'cloudflare' in response.headers.get('Server', '').lower():
            tech['CDN'] = 'Cloudflare'
        return jsonify({'detected': tech})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/hsts')
def hsts():
    domain = request.args.get('domain')
    try:
        response = requests.get(f'https://{domain}', timeout=5)
        hsts_header = response.headers.get('Strict-Transport-Security', 'Not Set')
        return jsonify({'HSTS': hsts_header})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/zone-transfer')
def zone_transfer():
    domain = request.args.get('domain')
    try:
        ns_records = dns.resolver.resolve(domain, 'NS')
        results = {}
        for ns in ns_records:
            try:
                zt = dns.query.xfr(str(ns), domain)
                zone = dns.zone.from_xfr(zt)
                results[str(ns)] = [str(n) for n in zone.nodes.keys()]
            except Exception:
                results[str(ns)] = 'Zone transfer failed'
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/dns-propagation')
def dns_propagation():
    return jsonify({'note': 'Implement with multiple resolvers or external services for DNS propagation check'})

@app.route('/expired-domain')
def expired_domain():
    domain = request.args.get('domain')
    try:
        w = whois.whois(domain)
        return jsonify({'expiration_date': str(w.expiration_date)})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/dnsdumpster')
def dnsdumpster():
    return jsonify({'note': 'Integrate with DNSDumpster scraping or API if available'})

if __name__ == '__main__':
    app.run(debug=True)

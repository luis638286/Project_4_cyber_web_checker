from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from urllib.parse import urlparse

app = Flask(__name__)
CORS(
    app,
    resources={
        r"/scan": {
            "origins": [
                "https://luis638286.github.io"
            ]
        }
    },
    methods=["POST"],
    allow_headers=["Content-Type"]
)

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url

def check_https(url):
    parsed = urlparse(url)
    return parsed.scheme == "https"

def check_redirect_to_https(url):
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        http_url = "http://" + parsed.netloc
        r = requests.get(http_url, allow_redirects=True, timeout=5)
        final_url = r.url
        return final_url.startswith("https://")
    except Exception:
        return None


def check_security_headers(headers):
    important_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ]

    missing = []
    present = []

    for h in important_headers:
        if h in headers:
            present.append(h)
        else:
            missing.append(h)

    return missing, present



def check_secure_cookies(response):
    unsafe = []
    if "set-cookie" in response.headers:
        cookies = response.headers.get("set-cookie", "").lower()
        if "httponly" not in cookies:
            unsafe.append("Missing HttpOnly")
        if "secure" not in cookies:
            unsafe.append("Missing Secure flag")
    return unsafe

@app.route("/health", methods=["GET"])
def health():
    return "OK", 200

@app.route("/scan", methods=["POST"])
def scan():
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    normalized = normalize_url(url)

    try:
        resp = requests.get(normalized, timeout=6)
    except Exception as e:
        return jsonify({
            "url": normalized,
            "ok": False,
            "error": f"Could not reach site: {type(e).__name__}"
        }), 502

    headers = resp.headers

    https_enabled = check_https(normalized)
    redirects_to_https = check_redirect_to_https(normalized)
    missing_headers, present_headers = check_security_headers(headers)
    cookie_issues = check_secure_cookies(resp)

    return jsonify({
    "url": normalized,
    "ok": True,
    "https": https_enabled,
    "redirects_to_https": redirects_to_https,
    "missing_headers": missing_headers,
    "present_headers": present_headers,
    "cookie_issues": cookie_issues,
    "status_code": resp.status_code,
}), 200


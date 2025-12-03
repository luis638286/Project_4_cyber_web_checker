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
                "https://luis638286.github.io",
            ]
        }
    },
    methods=["POST"],
    allow_headers=["Content-Type"],
)


def normalize_url(url: str) -> str:
    """
    Strip whitespace and ensure the URL has a scheme.
    Defaults to https:// if none is present.
    """
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
    return url


def check_https(url: str) -> bool:
    """
    Returns True if the normalized URL uses HTTPS.
    """
    parsed = urlparse(url)
    return parsed.scheme == "https"


def check_redirect_to_https(url: str):
    """
    Checks whether the HTTP version of the site redirects to HTTPS.

    Returns:
      True  -> redirects correctly to https
      False -> does not redirect to https
      None  -> could not be determined (e.g. no netloc or request failure)
    """
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
    """
    Splits important security headers into missing and present lists.
    """
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
    cookie_issues = []

    # requests stores cookies in response.cookies, not only headers
    for cookie in response.cookies:
        name = cookie.name.lower()

        # Check Secure flag
        if not cookie.secure:
            cookie_issues.append(f"{cookie.name}: Missing Secure flag")

        # Check HttpOnly flag
        if cookie.has_nonstandard_attr("HttpOnly") is False:
            cookie_issues.append(f"{cookie.name}: Missing HttpOnly")

    # As fallback, also check raw headers for Set-Cookie
    raw_set_cookie = response.headers.get("Set-Cookie") or response.headers.get("set-cookie")
    if raw_set_cookie:
        if "httponly" not in raw_set_cookie.lower():
            cookie_issues.append("Missing HttpOnly")
        if "secure" not in raw_set_cookie.lower():
            cookie_issues.append("Missing Secure flag")

    return cookie_issues


def calculate_risk(https_enabled, redirects_to_https, missing_headers, cookie_issues):
    """
    Returns (score_0_to_100, risk_level_str) based on weighted penalties.

    Higher score = better security.
    Lower score = higher risk.
    """
    score = 100

    # 1. HTTPS usage (most important)
    if not https_enabled:
        score -= 40  # major issue

    # 2. Redirect behaviour (important but slightly less critical)
    if redirects_to_https is False:
        score -= 20

    # 3. Missing headers – weighted by importance
    header_weights = {
        "Content-Security-Policy": 10,
        "Strict-Transport-Security": 10,
        "X-Frame-Options": 6,
        "X-Content-Type-Options": 6,
        "Referrer-Policy": 4,
        "Permissions-Policy": 4,
    }

    for h in missing_headers:
        score -= header_weights.get(h, 4)

    # 4. Cookie issues
    for issue in cookie_issues:
        if "httponly" in issue.lower():
            score -= 10
        elif "secure" in issue.lower():
            score -= 10
        else:
            score -= 5

    # Clamp between 0 and 100
    score = max(0, min(100, score))

    # Map numeric score to qualitative level
    if score >= 80:
        level = "Low"
    elif score >= 60:
        level = "Medium"
    elif score >= 40:
        level = "High"
    else:
        level = "Critical"

    return score, level


@app.route("/health", methods=["GET"])
def health():
    return "OK", 200


@app.route("/scan", methods=["POST"])
def scan():
    # Parse body
    try:
        data = request.get_json(force=True, silent=False)
    except Exception:
        return jsonify({"error": "Invalid JSON body"}), 400

    url = (data.get("url") or "").strip()
    if not url:
        return jsonify({"error": "URL is required"}), 400

    normalized = normalize_url(url)

    # Fetch the target website
    try:
        resp = requests.get(normalized, timeout=6)
    except Exception as e:
        return jsonify({
            "url": normalized,
            "ok": False,
            "error": f"Could not reach site: {type(e).__name__}",
        }), 502

    headers = resp.headers

    https_enabled = check_https(normalized)
    redirects_to_https = check_redirect_to_https(normalized)
    missing_headers, present_headers = check_security_headers(headers)
    cookie_issues = check_secure_cookies(resp)

    #  overall risk score + level
    security_score, risk_level = calculate_risk(
        https_enabled,
        redirects_to_https,
        missing_headers,
        cookie_issues,
    )

    return jsonify({
        "url": normalized,
        "ok": True,
        "https": https_enabled,
        "redirects_to_https": redirects_to_https,
        "missing_headers": missing_headers,
        "present_headers": present_headers,
        "cookie_issues": cookie_issues,
        "status_code": resp.status_code,
        "security_score": security_score,  # 0–100, higher = better
        "risk_level": risk_level,          # Low / Medium / High / Critical
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

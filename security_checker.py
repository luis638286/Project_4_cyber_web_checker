import requests
from urllib.parse import urlparse

def check_https(url):
    parsed = urlparse(url)
    return parsed.scheme == "https"

def check_redirect_to_https(url):
    try:
        r = requests.get(url, allow_redirects=True, timeout=5)
        final_url = r.url
        return final_url.startswith("https://")
    except:
        return False

def check_security_headers(headers):
    important_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    missing = []
    for h in important_headers:
        if h not in headers:
            missing.append(h)
    return missing

def check_secure_cookies(response):
    unsafe = []
    
    if 'set-cookie' in response.headers:
        cookies = response.headers.get('set-cookie').lower()
        
        if "httponly" not in cookies:
            unsafe.append("Missing HttpOnly")
        if "secure" not in cookies:
            unsafe.append("Missing Secure flag")
    
    return unsafe

def scan_website(url):
    print(f"\nScanning: {url}")
    print("------------------------------------")
  
    # Force http:// version to check redirect
    http_url = "http://" + urlparse(url).netloc

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
    except:
        print("❌ Could not reach site.")
        return

    # HTTPS check
    if check_https(url):
        print("✔ HTTPS is enabled")
    else:
        print("✖ HTTPS is NOT enabled")

    # Redirect check
    if check_redirect_to_https(http_url):
        print("✔ HTTP redirects to HTTPS correctly")
    else:
        print("✖ HTTP does NOT redirect to HTTPS")

    # Headers check
    missing_headers = check_security_headers(headers)
    if missing_headers:
        print("✖ Missing important security headers:")
        for h in missing_headers:
            print(f"   - {h}")
    else:
        print("✔ All important security headers present")

    # Cookie check
    cookie_issues = check_secure_cookies(response)
    if cookie_issues:
        print("✖ Cookie issues:")
        for issue in cookie_issues:
            print(f"   - {issue}")
    else:
        print("✔ Cookies are secure")

    print("------------------------------------")
    print("Done.\n")

# -----------------------------
# Run the scan
# -----------------------------

if __name__ == "__main__":
    target = input("Enter a full URL (example: https://example.com): ")
    scan_website(target)



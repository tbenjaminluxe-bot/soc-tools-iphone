# Phishing URL Detector V2 - SOC Lab 10
# Built on iPhone by Roland

import re
from urllib.parse import urlparse

BRANDS = ["google", "facebook", "instagram", "paypal", "amazon", "binance", "gtbank", "accessbank", "opay", "whatsapp", "telegram", "apple", "microsoft"]
SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "suspended", "confirm", "wallet", "free", "gift", "airdrop", "kyc"]
SHORTENERS = ["bit.ly", "tinyurl", "t.co", "is.gd", "cutt.ly", "shorte.st"]

def check(url):
    score = 0
    reasons = []
    url = url.strip().lower()
    if not url.startswith("http"):
        url = "http://" + url
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # 1. No HTTPS
    if parsed.scheme != "https":
        score += 20
        reasons.append("No HTTPS - not secure")

    # 2. IP address instead of domain
    if re.match(r"^\d+\.\d+\.\d+\.\d+", domain):
        score += 30
        reasons.append("Uses IP address instead of domain - HIGH RISK")

    # 3. URL shortener
    if any(s in domain for s in SHORTENERS):
        score += 20
        reasons.append("URL shortener - hides real destination")

    # 4. Too many subdomains / long URL
    if domain.count(".") >= 3:
        score += 10
        reasons.append("Too many subdomains - possible spoofing")
    if len(url) > 75:
        score += 10
        reasons.append("Very long URL")

    # 5. Typosquatting - brand + extra chars
    for brand in BRANDS:
        if brand in domain and domain != f"www.{brand}.com" and domain != f"{brand}.com":
            # e.g. google-secure.com, paypa1.com
            score += 30
            reasons.append(f"Possible typosquatting of '{brand}' -> {domain}")
            break

    # 6. Suspicious keywords
    for word in SUSPICIOUS_WORDS:
        if word in url:
            score += 10
            reasons.append(f"Phishing keyword found: '{word}'")
            break

    # 7. @ symbol trick
    if "@" in url:
        score += 20
        reasons.append("'@' in URL - hides real domain")

    # Verdict
    score = min(score, 100)
    print(f"\nURL: {url}")
    print(f"SCORE: {score}/100")
    if score >= 60:
        print("VERDICT: 🚨 MALICIOUS - DO NOT CLICK")
    elif score >= 30:
        print("VERDICT: ⚠️ SUSPICIOUS - VERIFY BEFORE CLICKING")
    else:
        print("VERDICT: ✅ LIKELY SAFE")
    print("Reasons:")
    for r in reasons or ["- No red flags found"]:
        print(f"- {r}")

    with open("phishing_report_v2.txt", "a") as f:
        f.write(f"{url} | {score}/100 | {reasons}\n")
    print("\n[SAVED] phishing_report_v2.txt")

print("=== PHISHING URL DETECTOR V2 ===")
while True:
    u = input("Paste URL to check (or type exit): ")
    if u.lower() == "exit":
        break
    check(u)

import requests
import re

def is_lower_version_captcha(html_content):
    """
    Attempt to detect reCAPTCHA versions.
    Returns True if it detects patterns indicative of v1 or v2, False if v3 or no captcha found.
    """
    # Check for reCAPTCHA v2 patterns:
    # Common pattern: <script src="https://www.google.com/recaptcha/api.js"
    # Also the presence of a g-recaptcha div often means v2
    if re.search(r'https://www\.google\.com/recaptcha/api\.js(\s|")', html_content) and 'g-recaptcha' in html_content:
        # This is likely reCAPTCHA v2
        return True
    
    # Check for known v1 patterns (v1 is deprecated, but if you have known markers, put them here):
    # Historically, reCAPTCHA v1 involved older iframe-based solutions, but it’s largely deprecated.
    # For illustration, a simple pattern might be:
    # <iframe src="https://www.google.com/recaptcha/api/legacy" (just an example, adapt if needed)
    if 'recaptcha/api/legacy' in html_content:
        return True

    # If we see a reCAPTCHA script with ?render=, it's likely v3:
    if 'recaptcha/api.js?render=' in html_content:
        # This indicates v3
        return False

    # If no known captcha patterns are found, we assume no captcha or something else.
    return False

def main():
    input_file = 'urls.txt'  # Change this to your input file
    with open(input_file, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    for url in urls:
        try:
            response = requests.get(url, timeout=10)
            html_content = response.text
            if is_lower_version_captcha(html_content):
                print(f"[+] Potentially lower-than-v3 CAPTCHA found on: {url}")
            else:
                print(f"[-] No lower-than-v3 CAPTCHA detected on: {url}")
        except requests.RequestException as e:
            print(f"[!] Error fetching {url}: {e}")

if __name__ == "__main__":
    main()

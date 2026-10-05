import argparse
import os
import re
import sys
import time
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

import requests
from dotenv import load_dotenv

load_dotenv()
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

VT_URL_ENDPOINT = "https://www.virustotal.com/api/v3/urls"
REQUEST_TIMEOUT = 30            # seconds before a request gives up
MIN_SECONDS_BETWEEN_CALLS = 15  # free VT API = 4 requests/minute
MAX_POLLS = 8                   # how many times to wait for a report to finish

URL_REGEX = re.compile(r'(?:https?://|www\.)[^\s<>"\']+', re.IGNORECASE)
TRAILING_JUNK = ".,;:!?)]}'\""

_last_call = 0.0


# ---------------------------------------------------------------- email parsing
class HrefParser(HTMLParser):
    """Collects every link from <a href="..."> tags in an HTML body."""

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag in ("a", "area"):
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value.strip())


def mail_inspector(file_path):
    try:
        with open(file_path, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
        print(f"[+] Successfully unrolled the scroll: {file_path}")
        return msg
    except FileNotFoundError:
        print(f"[-] Alas! No such scroll was found at path: {file_path}")
        return None


def get_part_text(part):
    """Decode a part using its declared charset; fall back to lenient decoding."""
    try:
        return part.get_content()
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", errors="ignore")


def normalize_url(url):
    url = url.strip().rstrip(TRAILING_JUNK)
    if url.lower().startswith("www."):
        url = "http://" + url
    return url


def extract_urls(msg):
    """Pull URLs from both text/plain and text/html parts (deduplicated, in order)."""
    found = []

    for part in msg.walk():
        if part.is_multipart() or part.get_content_disposition() == "attachment":
            continue

        ctype = part.get_content_type()
        if ctype == "text/plain":
            found.extend(URL_REGEX.findall(get_part_text(part)))
        elif ctype == "text/html":
            parser = HrefParser()
            parser.feed(get_part_text(part))
            found.extend(parser.links)

    urls, seen = [], set()
    for raw in found:
        url = normalize_url(raw)
        if not url.lower().startswith(("http://", "https://")):
            continue  # skips mailto:, tel:, #anchors, etc.
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


# ------------------------------------------------------------------- VirusTotal
def throttle():
    """Keep us under the free-tier rate limit."""
    global _last_call
    wait = MIN_SECONDS_BETWEEN_CALLS - (time.monotonic() - _last_call)
    if wait > 0:
        time.sleep(wait)
    _last_call = time.monotonic()


def vt_request(method, url, api_key, **kwargs):
    headers = {"accept": "application/json", "x-apikey": api_key}
    for attempt in range(2):
        throttle()
        response = requests.request(
            method, url, headers=headers, timeout=REQUEST_TIMEOUT, **kwargs
        )
        if response.status_code == 429 and attempt == 0:
            print("[!] Rate limit hit, resting for 60 seconds...")
            time.sleep(60)
            continue
        response.raise_for_status()
        return response.json()


def check_virustotal(target_url, api_key):
    """Submit a URL for scanning (POST)."""
    return vt_request("POST", VT_URL_ENDPOINT, api_key, data={"url": target_url})


def get_analysis_report(analysis_url, api_key):
    """Fetch an analysis report (GET)."""
    return vt_request("GET", analysis_url, api_key)


def wait_for_report(analysis_url, api_key):
    """VirusTotal scans asynchronously - poll until the analysis is 'completed'."""
    for _ in range(MAX_POLLS):
        report = get_analysis_report(analysis_url, api_key)
        status = report.get("data", {}).get("attributes", {}).get("status")
        if status == "completed":
            return report
        print(f"    ...status is '{status}', waiting for the oracle...")
    return None


def print_verdict(target, stats):
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)

    print("\n" + "=" * 40)
    print("       VIRUSTOTAL SECURITY VERDICT       ")
    print("=" * 40)
    print(f"Target URL : {target}")
    print(f"Malicious  : {malicious} engines flagged this")
    print(f"Suspicious : {suspicious} engines found it odd")
    print(f"Harmless   : {harmless} engines cleared it")
    print(f"Undetected : {undetected} engines had no data")

    if malicious > 0:
        print("\n🚨 WARNING: Malicious indicators detected! Exercise extreme caution!")
    elif suspicious > 0:
        print("\n⚠️  CAUTION: Some engines found this link suspicious.")
    else:
        print("\n✅ No engine flagged this link (not a guarantee of safety).")
    print("=" * 40 + "\n")


# ------------------------------------------------------------------------ main
def main():
    parser = argparse.ArgumentParser(description="Scan URLs in an .eml file with VirusTotal")
    parser.add_argument("eml_path", help="path to the .eml file")
    args = parser.parse_args()

    if not VT_API_KEY:
        sys.exit("[-] VIRUSTOTAL_API_KEY is missing. Add it to your .env file.")

    msg = mail_inspector(args.eml_path)
    if not msg:
        sys.exit(1)

    urls_found = extract_urls(msg)
    if not urls_found:
        print("[-] No URLs found within this scroll.")
        return

    print(f"[+] Total unique URLs harvested: {len(urls_found)}")
    print("[+] Commencing inspection of all paths...\n")

    for index, target in enumerate(urls_found, start=1):
        print(f"--- Inspecting Link [{index}/{len(urls_found)}] ---")
        print(f"Target URL : {target}")

        try:
            submit_result = check_virustotal(target, VT_API_KEY)
            analysis_link = submit_result["data"]["links"]["self"]
            print("[+] Waiting for the oracle's judgment...")

            report = wait_for_report(analysis_link, VT_API_KEY)
            if report is None:
                print("[-] The oracle took too long. Try this link again later.\n")
                continue

            stats = report["data"]["attributes"]["stats"]
            print_verdict(target, stats)

        except requests.exceptions.RequestException as e:
            print(f"[-] Network/API error: {e}\n")
        except (KeyError, ValueError):
            print("[-] Alas, the oracle returned an unexpected response.\n")


if __name__ == "__main__":
    main()
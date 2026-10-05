# D3tect

A small Python tool that checks a suspicious email for malicious links. It reads a saved `.eml` file, extracts every URL (from both plain-text and HTML bodies), and scans each one with the [VirusTotal](https://www.virustotal.com) API.

The script only reads the links. It never visits them.

## Setup

1. Install Python 3.8+ and the dependencies:

   ```
   python -m pip install requests python-dotenv
   ```

2. Get a free API key from your VirusTotal account.

3. Create a `.env` file next to `D3tect.py`:

   ```
   VIRUSTOTAL_API_KEY=your_key_here
   ```

## Usage

```
python D3tect.py "path\to\email.eml"
```

Wrap the path in quotes if it contains spaces.

To get an `.eml` file: in Gmail use **⋮ → Download message**; in Thunderbird use **Save As**; in Outlook use **Save As** and pick the `.eml` option if offered.

## Example output

```
--- Inspecting Link [1/3] ---
Target URL : http://example.com/login
========================================
       VIRUSTOTAL SECURITY VERDICT
========================================
Malicious  : 5 engines flagged this
Suspicious : 1 engines found it odd
Harmless   : 60 engines cleared it
Undetected : 20 engines had no data

🚨 WARNING: Malicious indicators detected!
```

## Notes

- The free VirusTotal tier allows 4 requests per minute, so the script waits between calls. Emails with many links take a while.
- "No engine flagged this link" does not guarantee a link is safe. Brand-new phishing pages are often undetected.
- `.msg` files (Outlook's default format) are not supported. Use `.eml`.

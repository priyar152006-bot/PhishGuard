PHISHGUARD - UPDATED VERSION

Main updates:
- DNS/domain resolution check
- IP address display
- Domain creation date via public RDAP
- Website/domain age display
- HTTPS certificate hostname check
- Brand typo/impersonation detection
- Known official-domain verification (including OpenAI)
- ML prediction used as one signal instead of the only decision
- Non-resolving domains are classified as Phishing
- Domain details and analysis signals shown in the report

RUN ON WINDOWS (VS CODE)
1. Open this project folder in VS Code.
2. Terminal -> New Terminal.
3. Create the environment once:
   python -m venv venv
4. If PowerShell blocks activation, run once per new PowerShell terminal:
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
5. Activate:
   venv\Scripts\Activate.ps1
6. Install packages once:
   python -m pip install -r requirements.txt
7. Run the app:
   python app.py
8. Open:
   http://127.0.0.1:5000

NEXT TIME:
   venv\Scripts\Activate.ps1
   python app.py

IMPORTANT:
DNS resolution proves that a domain currently resolves to an IP address; it does not by itself prove that a site is trustworthy. The app combines DNS, domain metadata, HTTPS, brand checks, URL structure and the ML model. No URL-only system can guarantee 100% correct classification for every website on the Internet.


UPDATED REPORT UI
==================
- The main page now keeps only the URL input and Analyze Website action in the scanner.
- Clicking Analyze Website opens the complete analysis in a NEW browser tab.
- The report contains 11 separate, vertically stacked cards.
- Cards use the same dark navy/neon blue-purple theme and include hover glow/lift effects.
- Detection Confidence is visualized as a donut chart with Legitimate vs Phishing risk values.
- The report adds live DNS, HTTPS, HTTP, page metadata and internal-link checks where available.
- Website purpose/audience are derived from available public page/domain signals; unknown details are shown as unavailable rather than invented.
- A live website cannot be guaranteed 100% safe by any automated detector.

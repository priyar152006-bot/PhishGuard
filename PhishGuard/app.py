from flask import Flask, render_template, request, redirect
import joblib
import re
import sqlite3
import socket
import requests
from bs4 import BeautifulSoup
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin
from html.parser import HTMLParser
from difflib import SequenceMatcher

app = Flask(__name__)

# URL-text ML model (trained on known phishing/legitimate URLs)
model = joblib.load("url_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

# Common brands/domains used for typo/impersonation detection.
# This is intentionally conservative: an exact official domain is trusted,
# while close spellings on a different domain are treated as suspicious.
OFFICIAL_DOMAINS = {
    "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca",
    "google.com", "google.co.in", "microsoft.com", "apple.com", "facebook.com",
    "instagram.com", "linkedin.com", "youtube.com", "github.com", "paypal.com",
    "netflix.com", "flipkart.com", "walmart.com", "ebay.com", "adobe.com",
    "spotify.com", "twitter.com", "x.com", "reddit.com", "whatsapp.com",
    "outlook.com", "live.com", "office.com", "dropbox.com", "zoom.us",
    "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "nvidia.com",
    "cloudflare.com", "stackoverflow.com", "telegram.org", "discord.com",
    "canva.com", "notion.so", "stripe.com", "shopify.com", "airbnb.com",
}

BRAND_NAMES = {
    "amazon", "google", "microsoft", "apple", "facebook", "instagram", "linkedin",
    "youtube", "github", "paypal", "netflix", "flipkart", "walmart", "ebay",
    "adobe", "spotify", "twitter", "reddit", "whatsapp", "outlook", "dropbox", "zoom",
    "openai", "chatgpt", "anthropic", "claude", "nvidia", "cloudflare", "stackoverflow",
    "telegram", "discord", "canva", "notion", "stripe", "shopify", "airbnb"
}

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "secure", "security", "account",
    "update", "confirm", "password", "wallet", "billing", "payment", "unlock",
    "recover", "webscr", "credential", "authenticate"
}



class WebsiteParser(HTMLParser):
    """Parse public HTML for title, metadata, headings, navigation and visible text."""
    def __init__(self):
        super().__init__()
        self.title_parts = []
        self.meta = {}
        self.links = []
        self.h1_parts = []
        self.h2_parts = []
        self.h3_parts = []
        self.jsonld_parts = []
        self.text_parts = []
        self.in_title = False
        self.in_h1 = False
        self.in_h2 = False
        self.in_h3 = False
        self.skip_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()
        if tag in {"script", "style", "noscript", "svg"}:
            self.skip_depth += 1
            return
        if tag == "title": self.in_title = True
        if tag == "h1": self.in_h1 = True
        if tag == "h2": self.in_h2 = True
        if tag == "h3": self.in_h3 = True
        if tag == "meta":
            key = (attrs.get("name") or attrs.get("property") or "").lower()
            content = (attrs.get("content") or "").strip()
            if key and content: self.meta[key] = content
        if tag == "script" and (attrs.get("type") or "").lower() == "application/ld+json":
            self.jsonld_parts.append("__JSONLD__")
        if tag == "a" and attrs.get("href"):
            self.links.append((attrs.get("href"), attrs.get("aria-label") or attrs.get("title") or ""))

    def handle_endtag(self, tag):
        tag = tag.lower()
        if self.skip_depth and tag in {"script", "style", "noscript", "svg"}:
            self.skip_depth -= 1
            return
        if tag == "title": self.in_title = False
        if tag == "h1": self.in_h1 = False
        if tag == "h2": self.in_h2 = False
        if tag == "h3": self.in_h3 = False

    def handle_data(self, data):
        if self.skip_depth: return
        text = re.sub(r"\s+", " ", data).strip()
        if not text: return
        if self.in_title: self.title_parts.append(text)
        if self.in_h1: self.h1_parts.append(text)
        if self.in_h2: self.h2_parts.append(text)
        if self.in_h3: self.h3_parts.append(text)
        self.text_parts.append(text)


def fetch_website_snapshot(url):
    """Fetch the public page and a few relevant internal pages for better site profiling."""
    result = {
        "http_status": "Not available", "page_title": "Not available",
        "description": "", "server": "Not available", "content_type": "Not available",
        "page_count": "Not available", "page_names": [], "fetch_status": "Not fetched",
        "visible_text": "", "headings": [], "jsonld": ""
    }
    headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131 Safari/537.36 PhishGuard/3.0", "Accept": "text/html,application/xhtml+xml"}
    try:
        response = requests.get(url, timeout=12, allow_redirects=True, headers=headers)
        result["http_status"] = str(response.status_code)
        result["server"] = response.headers.get("Server", "Not disclosed")
        result["content_type"] = response.headers.get("Content-Type", "Not available").split(";")[0]
        result["fetch_status"] = "Fetched successfully"
        if "text/html" not in result["content_type"].lower(): return result

        def parse_page(html):
            parser=WebsiteParser(); parser.feed(html[:4_000_000])
            title=" ".join(parser.title_parts).strip()
            desc=parser.meta.get("description", "") or parser.meta.get("og:description", "") or parser.meta.get("twitter:description", "")
            headings=list(dict.fromkeys(parser.h1_parts+parser.h2_parts+parser.h3_parts))
            visible=" ".join(parser.text_parts)
            # JSON-LD is often the best structured description of a modern website.
            return parser, title[:200], desc[:1000], visible[:18000], headings[:60]

        parser,title,desc,visible,headings=parse_page(response.text)
        result["page_title"]=title or "Not provided by page"
        result["description"]=desc
        result["visible_text"]=visible
        result["headings"]=headings

        base=response.url; origin=urlparse(base).netloc.lower()
        seen=set(); names=[]; candidates=[]
        for href, link_label in parser.links:
            absolute=urljoin(base, href).split("#",1)[0]
            parsed=urlparse(absolute)
            if parsed.scheme not in {"http","https"} or parsed.netloc.lower()!=origin: continue
            if absolute in seen: continue
            seen.add(absolute)
            path=parsed.path.strip("/")
            label=(link_label or "").strip()
            if not label:
                label="Home" if not path else path.rstrip("/").split("/")[-1].replace("-"," ").replace("_"," ").title()
            if label not in names: names.append(label[:80])
            probe=(label+" "+path).lower()
            if any(k in probe for k in ["about","service","product","solution","feature","pricing","company","what-we-do","course","program","shop","store","help","support","business"]):
                candidates.append(absolute)
        if "Home" not in names: names.insert(0,"Home")
        result["page_count"]=f"{len(names)} discoverable page(s)"
        result["page_names"]=names[:40]


        # Fetch up to three relevant internal pages. This is still lightweight, but it
        # dramatically improves purpose/user detection for sites with generic homepages.
        extra_text=[]; extra_headings=[]
        for target in list(dict.fromkeys(candidates))[:3]:
            try:
                r=requests.get(target,timeout=7,allow_redirects=True,headers=headers)
                if "text/html" not in r.headers.get("Content-Type","").lower(): continue
                _,t,d,v,h=parse_page(r.text)
                extra_text.extend([t,d,v]); extra_headings.extend(h)
            except requests.RequestException:
                continue
        if extra_text:
            result["visible_text"]=(result["visible_text"]+" "+" ".join(extra_text))[:30000]
            result["headings"]=list(dict.fromkeys(result["headings"]+extra_headings))[:100]
        return result
    except requests.RequestException as exc:
        result["fetch_status"]=f"Could not fetch page: {type(exc).__name__}"
        return result
    except Exception as exc:
        result["fetch_status"]=f"Could not parse page: {type(exc).__name__}"
        return result


def infer_site_profile(domain, page_title, description, visible_text="", headings=None, page_names=None):
    """Determine a site's purpose from live public content, with layered fallbacks."""
    headings=headings or []; page_names=page_names or []
    raw=" ".join([domain or "",page_title or "",description or "",visible_text or ""," ".join(headings)," ".join(page_names)])
    text=re.sub(r"[^a-z0-9@._/-]+"," ",raw.lower())
    compact=" ".join(text.split())

    known={
      "amazon":("E-commerce / Online Shopping","The website is primarily used for online shopping, product discovery, purchasing and related digital services.","Consumers, shoppers, sellers and businesses."),
      "google":("Search Engine & Internet Services","The website is primarily used for web search and access to internet-based tools and services.","General internet users, students, professionals, developers and organizations."),
      "youtube":("Online Video & Media","The platform is primarily used to watch, publish, discover and share video content.","Viewers, creators, educators, businesses and media audiences."),
      "github":("Software Development & Collaboration","The platform is primarily used to host source code, manage software projects and collaborate on software development.","Developers, students, open-source communities and software teams."),
      "linkedin":("Professional Networking & Careers","The platform is primarily used for professional networking, careers, hiring and industry-related content.","Students, job seekers, professionals, recruiters and organizations."),
      "instagram":("Social Media & Content Sharing","The platform is primarily used to share, discover and interact with visual social content.","Social-media users, creators, brands and organizations."),
      "facebook":("Social Networking & Community","The platform is primarily used for social networking, communication, communities and content sharing.","General users, communities, creators, businesses and organizations."),
      "paypal":("Online Payments","The service is primarily used for online payments, transfers and payment management.","Consumers, merchants and organizations using digital payments."),
      "netflix":("Video Streaming & Entertainment","The service is primarily used to stream movies, series and other entertainment content.","Viewers, households and entertainment audiences."),
      "spotify":("Music Streaming","The service is primarily used to listen to, discover and manage music and audio content.","Listeners, artists, creators and audio audiences."),
      "canva":("Graphic Design & Visual Content Creation","The platform is primarily used to create presentations, graphics, documents, social posts and other visual content.","Students, creators, marketers, businesses, educators and organizations."),
      "microsoft":("Software, Cloud & Productivity Services","The website provides software, cloud, productivity and digital services from Microsoft.","Consumers, students, developers, businesses and organizations."),
      "apple":("Consumer Technology & Digital Services","The website provides information about Apple products, software and digital services.","Consumers, students, professionals and organizations."),
    }
    brand=(registered_domain(domain).split(".")[0] if domain else "").lower()
    if brand in known: return known[brand]

    categories={
      "E-commerce / Online Shopping":(["shop","shopping","store","cart","checkout","product","products","buy","order","orders","price","marketplace","delivery","fashion"],"The retrieved website content contains strong commerce, product or purchasing signals, so it appears to be an online shopping or retail service.","Customers, shoppers, buyers, sellers or businesses."),
      "Education / Learning":(["course","courses","learn","learning","education","university","college","school","student","students","training","lesson","degree","admission","faculty","academy","tutorial"],"The retrieved content contains strong education and learning signals, indicating an educational, academic or training purpose.","Students, learners, educators, teachers, researchers or training participants."),
      "News / Information":(["news","breaking news","article","articles","journal","journalism","headline","editorial","press","newsroom","reporting"],"The retrieved content contains publishing and news signals, indicating an information or media purpose.","Readers, viewers, subscribers and people seeking published information."),
      "Finance / Financial Services":(["bank","banking","finance","financial","investment","investing","loan","insurance","credit","mortgage","mutual fund","trading","account balance"],"The retrieved content contains financial-service signals, indicating banking, finance, investment, insurance or payment-related services.","Customers, account holders, investors, borrowers, merchants or financial-service users."),
      "Social Media / Community":(["follow","followers","friends","posts","stories","community","social","share","messages","profile","reels","feed","likes"],"The retrieved content contains strong social-networking or community signals, indicating a platform for user interaction and content sharing.","General users, creators, communities, brands or organizations."),
      "Software / Technology":(["software","developer","developers","api","cloud","technology","documentation","download","platform","code","repository","saas","app","application","hosting"],"The retrieved content contains software, developer, cloud or technology signals, indicating a technology-focused service or product.","Developers, technical users, students, businesses or organizations."),
      "Government / Public Services":(["government","gov","citizen","municipality","ministry","department","official portal","public service","tax","passport","district","state government"],"The retrieved content contains government or public-service signals, indicating an official information or service portal.","Citizens, residents, businesses or other public-service users."),
      "Healthcare / Medical Services":(["health","healthcare","hospital","clinic","doctor","medical","medicine","patient","appointment","pharmacy","wellness","diagnosis"],"The retrieved content contains healthcare or medical-service signals, indicating health information or patient-related services.","Patients, families, healthcare professionals or people seeking health services."),
      "Travel / Hospitality":(["hotel","hotels","flight","flights","travel","trip","booking","reservation","holiday","vacation","airport","rooms","tour"],"The retrieved content contains travel or hospitality signals, indicating booking, accommodation, transport or travel services.","Travelers, tourists, guests, families and business travelers."),
      "Real Estate":(["property","properties","real estate","homes","house","apartment","rent","rental","buy property","land","broker"],"The retrieved content contains property and housing signals, indicating a real-estate listing, rental or property service.","Home buyers, sellers, tenants, landlords, investors or property professionals."),
      "Jobs / Recruitment":(["job","jobs","career","careers","vacancy","vacancies","recruitment","recruiter","hiring","employment","resume","salary"],"The retrieved content contains employment and recruitment signals, indicating a jobs or career service.","Job seekers, recruiters, employers, students and professionals."),
      "Entertainment / Media":(["movie","movies","music","games","gaming","streaming","video","entertainment","watch","listen","podcast","lyrics"],"The retrieved content contains entertainment or media signals, indicating content consumption or entertainment services.","Viewers, listeners, players, fans, creators or general audiences."),
      "Nonprofit / Community Organization":(["nonprofit","non-profit","charity","donate","donation","volunteer","foundation","ngo","mission","community support"],"The retrieved content contains nonprofit, charity or community-support signals, indicating an organization focused on a social or public-interest mission.","Donors, volunteers, beneficiaries, members and community supporters."),
    }
    scored=[]
    for name,(words,exp,users) in categories.items():
        score=0
        matched=[]
        for w in words:
            # phrase-aware matching; longer phrases carry more weight
            if re.search(r"(?<![a-z])"+re.escape(w)+r"(?![a-z])",compact):
                score += 2 if " " in w else 1
                matched.append(w)
        scored.append((score,name,exp,users,matched))
    scored.sort(reverse=True,key=lambda x:x[0])
    best=scored[0]
    if best[0]>=2:
        explanation=best[2]
        if best[4]: explanation += " Key public signals included: " + ", ".join(best[4][:6]) + "."
        return best[1], explanation, best[3]

    # Last-resort title/domain/path interpretation. It is better than a misleading
    # generic label, while still being explicit that the inference is limited.
    tokens=re.sub(r"[-_.:/]+"," ",domain+" "+page_title+" "+" ".join(page_names)).lower()
    if any(x in tokens for x in ["blog","personal"]):
        return "Blog / Personal Website","The website appears to publish personal, editorial or blog-style content based on its public title, domain and navigation signals.","Readers, followers or visitors interested in the published content."
    if any(x in tokens for x in ["portfolio","designer","developer"]):
        return "Portfolio / Professional Website","The website appears to present a person's or organization's professional work, services or profile based on its public title and navigation.","Potential clients, employers, collaborators and general visitors."
    return ("Purpose could not be confidently verified",
            "PhishGuard retrieved the public website content, but the available title, description, headings and navigation did not provide enough reliable evidence to name a specific primary purpose. The system does not invent a purpose when evidence is insufficient.",
            "The intended audience could not be confidently verified from the publicly retrievable content.")


def build_findings(analysis, snapshot, brand_bad):
    findings = []
    if analysis["dns_status"] == "Resolved":
        findings.append({"level":"good","title":"DNS domain resolution","detail":"The domain currently resolves to an IP address, so the hostname is reachable through DNS."})
    else:
        findings.append({"level":"danger","title":"DNS resolution failed","detail":"The domain did not currently resolve through DNS. A non-resolving domain cannot be treated as a verified live legitimate website."})
    if analysis["https_status"] == "Verified":
        findings.append({"level":"good","title":"HTTPS certificate verified","detail":"The TLS certificate hostname check succeeded for this HTTPS address."})
    elif analysis["https_status"] == "Not verified":
        findings.append({"level":"warning","title":"HTTPS certificate not verified","detail":"A certificate check could not be completed successfully for this hostname."})
    else:
        findings.append({"level":"warning","title":"HTTPS not applicable","detail":"The submitted address does not use HTTPS."})
    if brand_bad:
        findings.append({"level":"danger","title":"Possible brand impersonation","detail":"The domain resembles a known brand but is not the verified official registered domain."})
    if snapshot["http_status"].isdigit() and int(snapshot["http_status"]) >= 400:
        findings.append({"level":"warning","title":"HTTP response issue","detail":f"The website returned HTTP status {snapshot['http_status']} during the live page check."})
    if analysis["official_domain"]:
        findings.append({"level":"good","title":"Known official domain","detail":"The registered domain matches a domain in PhishGuard's curated official-domain list."})
    if not brand_bad and analysis["dns_status"] == "Resolved" and analysis["https_status"] == "Verified":
        findings.append({"level":"good","title":"No high-risk signal from these checks","detail":"The live DNS, HTTPS and domain-identity checks did not produce a high-risk finding. This is not a guarantee that every page or future content is safe."})
    return findings


def init_db():
    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT, result TEXT,
        confidence REAL, scan_time TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS reviews(
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, rating INTEGER,
        review TEXT, review_time TEXT)""")
    conn.commit()
    conn.close()


def save_history(url, result, confidence):
    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scan_history(url,result,confidence,scan_time) VALUES(?,?,?,datetime('now','localtime'))",
                   (url, result, confidence))
    cursor.execute("DELETE FROM scan_history WHERE id NOT IN (SELECT id FROM scan_history ORDER BY id DESC LIMIT 6)")
    conn.commit(); conn.close()


def get_history():
    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT url,result,confidence,scan_time FROM scan_history ORDER BY id DESC LIMIT 6")
    rows = cursor.fetchall(); conn.close(); return rows


def save_review(name, rating, review):
    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO reviews(name,rating,review,review_time) VALUES(?,?,?,datetime('now','localtime'))",
                   (name, rating, review))
    cursor.execute("DELETE FROM reviews WHERE id NOT IN (SELECT id FROM reviews ORDER BY id DESC LIMIT 3)")
    conn.commit(); conn.close()


def get_reviews():
    conn = sqlite3.connect("history.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name,rating,review,review_time FROM reviews ORDER BY id DESC")
    rows = cursor.fetchall(); conn.close(); return rows


init_db()


def normalize_url(value):
    value = value.strip()
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    return value


def parse_domain(url):
    parsed = urlparse(normalize_url(url))
    return (parsed.hostname or "").lower().rstrip(".")


def registered_domain(host):
    # Lightweight eTLD approximation for the project's dependencies.
    # Handles normal domains and common two-level country domains.
    parts = host.split(".")
    if len(parts) < 2:
        return host
    two_level = {"co.uk", "co.in", "com.au", "co.jp", "co.nz", "com.br", "com.cn"}
    suffix = ".".join(parts[-2:])
    if suffix in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix


def is_valid_url(url):
    try:
        parsed = urlparse(normalize_url(url))
        host = parsed.hostname
        if parsed.scheme not in {"http", "https"} or not host:
            return False
        if "." not in host and not re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            return False
        return True
    except Exception:
        return False


def levenshtein_like_similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()


def brand_impersonation(domain):
    """Return (is_suspicious, reason). Detect close brand spellings and fake subdomains."""
    reg = registered_domain(domain)
    reg_name = reg.split(".")[0]
    host_lower = domain.lower()

    if reg in OFFICIAL_DOMAINS:
        return False, "Official domain match"

    # A brand appearing in a subdomain/path-like hostname is suspicious when
    # the registered domain is different (e.g. amazon.example.com).
    for brand in BRAND_NAMES:
        if brand in host_lower and reg_name != brand:
            return True, f"Possible {brand.title()} impersonation"

    # Typo-squatting: a domain label very close to a known brand but not equal.
    compact = re.sub(r"[^a-z0-9]", "", reg_name)
    for brand in BRAND_NAMES:
        if len(compact) >= 4:
            score = levenshtein_like_similarity(compact, brand)
            if score >= 0.80 and compact != brand:
                return True, f"Domain name is very similar to {brand.title()}"

    return False, ""


def structural_signals(url):
    """Return a 0..1 risk score and human-readable reasons from URL structure."""
    parsed = urlparse(normalize_url(url))
    host = parsed.hostname or ""
    full = url.lower()
    risk = 0.0
    reasons = []

    try:
        socket.inet_aton(host)
        risk += 0.30; reasons.append("Uses an IP address instead of a normal domain")
    except OSError:
        pass

    if len(full) > 100:
        risk += 0.12; reasons.append("Unusually long URL")
    if len(full) > 180:
        risk += 0.10
    if "@" in full:
        risk += 0.20; reasons.append("Contains @ in the URL")
    if "//" in parsed.path:
        risk += 0.10; reasons.append("Contains a redirect-like // in the path")
    if full.count("-") >= 4:
        risk += 0.08; reasons.append("Contains many hyphens")
    if len(host.split(".")) >= 5:
        risk += 0.08; reasons.append("Has an unusually deep subdomain")

    for word in SUSPICIOUS_WORDS:
        if word in full and word not in host:
            risk += 0.015
    if any(w in full for w in SUSPICIOUS_WORDS):
        reasons.append("Contains a security/login-related keyword")

    if parsed.scheme == "http":
        risk += 0.08; reasons.append("Uses HTTP instead of HTTPS")

    return min(risk, 0.90), reasons


def resolve_ip(domain):
    """Return a public DNS-resolved IPv4 address when available."""
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        for info in infos:
            ip = info[4][0]
            if ip:
                return ip
    except Exception:
        pass
    return None


def domain_reachable(domain):
    """Return True when DNS currently resolves the domain."""
    return resolve_ip(domain) is not None


def parse_rdap_date(value):
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).date()
    except Exception:
        return None


def get_registration_info(domain):
    """Get domain creation/registration date from public RDAP when available."""
    if not domain or re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", domain):
        return None, None
    try:
        response = requests.get(
            f"https://rdap.org/domain/{domain}",
            timeout=6,
            headers={"User-Agent": "PhishGuard/2.0"}
        )
        if response.status_code != 200:
            return None, None
        data = response.json()
        registration = None
        for event in data.get("events", []):
            if str(event.get("eventAction", "")).lower() in {"registration", "registered"}:
                registration = parse_rdap_date(event.get("eventDate", ""))
                break
        if registration:
            today = datetime.now(timezone.utc).date()
            if registration > today:
                return registration, "Not available"
            # Calendar-based age without adding another dependency.
            years = today.year - registration.year
            months = today.month - registration.month
            days = today.day - registration.day
            if days < 0:
                months -= 1
            if months < 0:
                years -= 1
                months += 12
            if years == 0 and months == 0:
                age = f"{max(days, 0)} day(s)"
            elif years == 0:
                age = f"{months} month(s)"
            elif months == 0:
                age = f"{years} year(s)"
            else:
                age = f"{years} year(s) {months} month(s)"
            return registration, age
    except Exception as exc:
        print("RDAP lookup failed:", exc)
    return None, None


def certificate_matches(url):
    """Best-effort TLS hostname check. Returns None when not applicable/unavailable."""
    parsed = urlparse(normalize_url(url))
    if parsed.scheme != "https" or not parsed.hostname:
        return None
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                ssl.match_hostname(ssock.getpeercert(), parsed.hostname)
        return True
    except Exception:
        return False


def analyze_url(url):
    """Combine ML with DNS, domain-age, HTTPS and anti-impersonation checks."""
    clean = normalize_url(url)
    domain = parse_domain(clean)
    reg = registered_domain(domain)

    official = reg in OFFICIAL_DOMAINS
    resolved_ip = resolve_ip(domain)
    reachable = resolved_ip is not None
    registration_date, website_age = get_registration_info(reg)

    # ML prediction is used as one signal, not as the sole authority.
    vector = vectorizer.transform([clean.lower()])
    probabilities = model.predict_proba(vector)[0]
    classes = list(model.classes_)
    p_bad = float(probabilities[classes.index("bad")]) if "bad" in classes else 0.5
    p_good = float(probabilities[classes.index("good")]) if "good" in classes else 1.0 - p_bad

    structural_risk, reasons = structural_signals(clean)
    brand_bad, brand_reason = brand_impersonation(domain)
    if brand_bad:
        reasons.insert(0, brand_reason)

    if not reachable:
        reasons.insert(0, "Domain does not currently resolve in DNS")

    cert = certificate_matches(clean)
    if cert is False:
        reasons.append("HTTPS certificate could not be verified for this hostname")

    if registration_date is None and reachable:
        reasons.append("Domain registration date is unavailable from RDAP")

    # A known official registered domain must not be overridden by URL-text ML.
    # This fixes false positives such as openai.com/index/chatgpt/.
    if official and reachable:
        risk = min(structural_risk * 0.35, 0.25)
        classification = "Safe"
        confidence = max(95.0, (1.0 - risk) * 100.0)
    elif not reachable:
        # A URL whose domain cannot currently resolve is not a live legitimate site.
        classification = "Phishing"
        risk = 1.0
        confidence = 99.0
    elif brand_bad:
        classification = "Phishing"
        risk = max(0.85, p_bad * 0.60 + structural_risk * 0.15 + 0.25)
        confidence = min(99.0, risk * 100.0)
    else:
        # For unknown but live domains, ML remains useful while DNS/HTTPS/age
        # provide additional evidence. We do not claim certainty.
        risk = p_bad * 0.55 + structural_risk * 0.25
        if cert is False:
            risk += 0.08
        if registration_date is not None:
            today = datetime.now(timezone.utc).date()
            age_days = (today - registration_date).days
            if age_days < 30:
                risk += 0.10
            elif age_days < 90:
                risk += 0.05
        risk = max(0.0, min(1.0, risk))
        classification = "Phishing" if risk >= 0.50 else "Safe"
        confidence = (risk if classification == "Phishing" else 1.0 - risk) * 100.0

    # If the ML model strongly disagrees with a verified official domain, explain why.
    if official and p_bad >= 0.50:
        reasons.append("Known official domain: ML URL score was overridden by domain verification")

    snapshot = fetch_website_snapshot(clean) if reachable else {
        "http_status":"Not available", "page_title":"Not available", "description":"",
        "server":"Not available", "content_type":"Not available", "page_count":"Not available",
        "page_names":[], "fetch_status":"Skipped because DNS did not resolve"
    }
    website_name = reg.split(".")[0].replace("-", " ").replace("_", " ").title() if reg else "Unknown Website"
    purpose, purpose_explanation, target_users = infer_site_profile(reg, snapshot["page_title"], snapshot["description"], snapshot.get("visible_text", ""), snapshot.get("headings", []), snapshot.get("page_names", []))
    if website_name.lower() in {"Amazon".lower(),"Google".lower(),"Microsoft".lower(),"Apple".lower(),"Facebook".lower(),"Instagram".lower(),"Linkedin".lower(),"Youtube".lower(),"Github".lower(),"Paypal".lower()}:
        pass
    description = snapshot["description"] or (snapshot["page_title"] if snapshot["page_title"] != "Not available" else "No public description was available from the landing page.")
    status_explanation = (
        "The verified domain and live technical checks support a legitimate classification." if classification == "Safe" else
        "The analysis found one or more high-risk indicators. The result should be treated as unsafe until independently verified."
    )
    confidence_explanation = (
        "This confidence is the combined decision score from the URL model and live technical signals; it is not a guarantee of safety."
    )
    final_reason = (
        "The final classification combines machine-learning URL signals with domain, DNS, HTTPS and impersonation checks. "
        "The individual evidence below explains the decision."
    )
    findings = build_findings({"dns_status":"Resolved" if reachable else "Not resolved", "https_status":("Verified" if cert is True else "Not verified" if cert is False else "Not applicable"), "official_domain":official}, snapshot, brand_bad)

    return {
        "classification": classification,
        "confidence": round(confidence, 2),
        "reasons": reasons,
        "safe_value": round((1.0 - risk) * 100.0, 2),
        "phishing_value": round(risk * 100.0, 2),
        "domain": domain,
        "ip_address": resolved_ip or "Not available",
        "dns_status": "Resolved" if reachable else "Not resolved",
        "registration_date": registration_date.isoformat() if registration_date else "Not available",
        "website_age": website_age or "Not available",
        "https_status": ("Verified" if cert is True else "Not verified" if cert is False else "Not applicable"),
        "ml_phishing": round(p_bad * 100.0, 2),
        "ml_safe": round(p_good * 100.0, 2),
        "official_domain": official,
        "website_name": website_name,
        "website_description": description,
        "public_content_signals": snapshot.get("headings", []),
        "status_explanation": status_explanation,
        "confidence_explanation": confidence_explanation,
        "registration_source": "Public RDAP" if registration_date else "Not available",
        "page_count": snapshot["page_count"],
        "page_names": snapshot["page_names"],
        "page_explanation": "This is the number of unique internal links discovered on the fetched public page; it is not a count of browser tabs opened by the site." if snapshot["page_names"] else "The public page could not provide a verified internal-page count during this scan.",
        "main_purpose": purpose,
        "purpose_explanation": purpose_explanation,
        "target_users": target_users,
        "users_explanation": f"{target_users} This audience assessment is based on the website domain, page title, description and other publicly retrievable signals from the scanned page. It is not a claim that access is restricted to these groups.",
        "http_status": snapshot["http_status"],
        "page_title": snapshot["page_title"],
        "server": snapshot["server"],
        "content_type": snapshot["content_type"],
        "fetch_status": snapshot["fetch_status"],
        "findings": findings,
        "final_reason": final_reason,
    }


def is_valid_search_query(query):
    """Reject empty/gibberish queries while allowing normal words and phrases."""
    q = re.sub(r"\s+", " ", query.strip())
    if not q or len(q) < 2 or len(q) > 120:
        return False, "Please enter a valid search topic or website."
    if not re.search(r"[A-Za-z0-9]", q):
        return False, "Please enter a valid search topic or website."
    # Reject strings made almost entirely from one repeated character.
    compact = re.sub(r"[^A-Za-z0-9]", "", q).lower()
    if len(compact) >= 6 and len(set(compact)) <= 2:
        return False, "Please enter a meaningful search topic or website."
    if len(compact) >= 10 and max(compact.count(ch) for ch in set(compact)) / len(compact) >= 0.80:
        return False, "Please enter a meaningful search topic or website."
    # Common keyboard-smash patterns.
    keyboard_smashes = {
        "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbnm",
        "poiuytrewq", "lkjhgfdsa", "mnbvcxz"
    }
    if compact in keyboard_smashes or any(len(p) >= 6 and p in compact for p in keyboard_smashes):
        return False, "Please enter a meaningful search topic or website."
    return True, ""


def web_search(query):
    """Fetch real web-search results with robust DuckDuckGo/Bing fallbacks."""
    query = query.strip()
    if not query:
        return []

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/130.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    }

    def clean_url(href):
        if not href:
            return ""
        href = href.strip()
        if href.startswith("//"):
            href = "https:" + href
        # DuckDuckGo redirect links contain the real URL in `uddg`.
        try:
            parsed = urlparse(href)
            qs = parse_qs(parsed.query)
            if "uddg" in qs and qs["uddg"]:
                href = unquote(qs["uddg"][0])
        except Exception:
            pass
        if href.startswith(("http://", "https://")):
            return href
        return ""

    def add_result(results, seen, title, href, snippet=""):
        href = clean_url(href)
        title = BeautifulSoup(title or "", "html.parser").get_text(" ", strip=True)
        snippet = BeautifulSoup(snippet or "", "html.parser").get_text(" ", strip=True)
        if not href or not title:
            return
        key = href.rstrip("/").lower()
        if key in seen:
            return
        seen.add(key)
        results.append({"title": title, "url": href, "snippet": snippet})

    # 1) DuckDuckGo HTML
    try:
        response = requests.get(
            "https://html.duckduckgo.com/html/",
            params={"q": query},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        results, seen = [], set()
        for item in soup.select(".result, article[data-testid='result']"):
            link = item.select_one(".result__a, a[data-testid='result-title-a']")
            snippet = item.select_one(".result__snippet, [data-result='snippet']")
            if link:
                add_result(results, seen, link.get_text(" ", strip=True),
                           link.get("href", ""),
                           snippet.get_text(" ", strip=True) if snippet else "")
            if len(results) >= 10:
                return results
        if results:
            return results
    except Exception as exc:
        print("DuckDuckGo search failed:", exc)

    # 2) Bing fallback
    try:
        response = requests.get(
            "https://www.bing.com/search",
            params={"q": query},
            headers=headers,
            timeout=10,
        )
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")
        results, seen = [], set()
        for item in soup.select("li.b_algo"):
            link = item.select_one("h2 a")
            snippet = item.select_one(".b_caption p")
            if link:
                add_result(results, seen, link.get_text(" ", strip=True),
                           link.get("href", ""),
                           snippet.get_text(" ", strip=True) if snippet else "")
            if len(results) >= 10:
                break
        return results
    except Exception as exc:
        print("Bing search failed:", exc)
        return []


@app.route("/search")
def search_page():
    query = request.args.get("q", "").strip()
    results = []
    search_error = ""
    if query:
        valid, search_error = is_valid_search_query(query)
        if valid:
            results = web_search(query)
            if not results:
                search_error = "No reliable results found. Try a different search topic."
    return render_template("search.html", query=query, results=results, search_error=search_error)


@app.route("/detector", methods=["GET", "POST"])
def detector_page():
    entered_url = ""
    analysis = None
    error = None
    if request.method == "POST":
        entered_url = request.form.get("url", "").strip()
        if not entered_url:
            error = "Please enter a website URL."
        elif not is_valid_url(entered_url):
            error = "Invalid website URL. Please enter a complete HTTP or HTTPS address."
        else:
            try:
                analysis = analyze_url(entered_url)
                save_history(entered_url, analysis["classification"], analysis["confidence"])
            except Exception as e:
                print("Analysis error:", e)
                error = "An unexpected error occurred while analyzing this URL. Please try again."
    return render_template("detector.html", entered_url=entered_url, analysis=analysis, error=error)


@app.route("/")
def home():
    return render_template("index.html", reviews=get_reviews())


@app.route("/history")
def history_page():
    return render_template("history.html", history=get_history())


@app.route("/review")
def review_page():
    return render_template("review.html", submitted=request.args.get("submitted") == "1")


@app.route("/submit_review", methods=["POST"])
def submit_review():
    name = request.form.get("name", "Anonymous")
    try:
        rating = int(request.form.get("rating", 5))
    except ValueError:
        rating = 5
    review = request.form.get("review", "")
    save_review(name, rating, review)
    return redirect("/review?submitted=1")


@app.route("/predict", methods=["POST"])
def predict():
    # Backward-compatible endpoint: analysis stays on the Threat Detector page.
    entered_url = request.form.get("url", "").strip()
    if not entered_url:
        return render_template("detector.html", entered_url="", analysis=None, error="Please enter a website URL.")
    if not is_valid_url(entered_url):
        return render_template("detector.html", entered_url=entered_url, analysis=None, error="Invalid website URL. Please enter a complete HTTP or HTTPS address.")
    try:
        analysis = analyze_url(entered_url)
        save_history(entered_url, analysis["classification"], analysis["confidence"])
        return render_template("detector.html", entered_url=entered_url, analysis=analysis, error=None)
    except Exception as e:
        print("Analysis error:", e)
        return render_template("detector.html", entered_url=entered_url, analysis=None, error="An unexpected error occurred while analyzing this URL. Please try again."), 500


if __name__ == "__main__":
    app.run(debug=True)

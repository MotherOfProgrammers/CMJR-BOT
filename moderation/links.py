import ipaddress
import re
import unicodedata
from urllib.parse import urlparse

from database.database import is_trusted_domain


URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\"]+",
    re.IGNORECASE,
)

BARE_DOMAIN_PATTERN = re.compile(
    r"(?<![@\w])(?:[a-z0-9-]+\.)+"
    r"(?:com|net|org|io|xyz|top|club|online|site|shop|info|biz|me|"
    r"pay|vip|app|cc|cn|ru|ga|tk|ml|cf|gq|to|co|link)(?:/[^\s<>\"']*)?",
    re.IGNORECASE,
)

IP_PATTERN = re.compile(
    r"^\d{1,3}(\.\d{1,3}){3}$"
)

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "goo.gl",
    "rebrand.ly",
    "cutt.ly",
    "ow.ly",
    "shorturl.at",
    "tiny.cc",
    "buff.ly",
    "lnkd.in",
    "rb.gy",
}

REDIRECTORS = {
    "redirect",
    "redir",
    "click",
    "link",
    "out",
    "exit",
    "url",
    "dest",
    "go",
    "open",
}

SUSPICIOUS_TLDS = {
    "tk",
    "ml",
    "ga",
    "cf",
    "gq",
    "xyz",
    "top",
    "vip",
    "win",
    "bid",
    "loan",
    "click",
    "zip",
    "mov",
}

CREDENTIAL_PATHS = {
    "/login",
    "/signin",
    "/verify",
    "/verification",
    "/secure",
    "/account",
    "/auth",
    "/wallet",
    "/password",
    "/reset",
    "/confirm",
    "/validate",
    "/2fa",
    "/otp",
    "/recover",
}

PAYMENT_KEYWORDS = {
    "pay",
    "payment",
    "payout",
    "invoice",
    "checkout",
    "charge",
    "cashapp",
    "paypal",
    "bitcoin",
    "crypto",
    "wallet",
    "bank",
    "wire",
}

PHISHING_KEYWORDS = {
    "phishing",
    "web-login",
    "account-alert",
    "suspended",
    "unusual-activity",
    "unauthorized",
    "verify-identity",
    "secure-your-account",
    "confirm-identity",
    "update-information",
    "login-free-gift",
    "claim-prize",
    "lottery",
    "inheritance",
}

LOOKALIKE_KEYWORDS = {
    "paypal",
    "apple",
    "google",
    "microsoft",
    "amazon",
    "netflix",
    "facebook",
    "whatsapp",
    "instagram",
    "binance",
    "coinbase",
    "dhl",
    "fedex",
    "your-bank",
}

ADULT_DOMAIN_SUFFIXES = {
    "xvideos.com",
    "xnxx.com",
    "xhamster.com",
    "pornhub.com",
    "youporn.com",
    "redtube.com",
    "spankbang.com",
    "tube8.com",
    "porn.com",
    "onlyfans.com",
    "fansly.com",
    "manyvids.com",
    "bangbros.com",
    "brazzers.com",
    "realitykings.com",
    "motherless.com",
    "pornhd.com",
    "xvideos2.com",
    "chaturbate.com",
    "hanime.tv",
    "nhentai.net",
    "hentaihaven.org",
    "javhd.com",
}

ADULT_TLDS = {
    "xxx",
}

ADULT_KEYWORD_TOKENS = {
    "nsfw",
    "nsfl",
    "porn",
    "porno",
    "adult",
    "xxx",
    "xxx18",
    "18plus",
    "r18",
    "sex",
    "sexy",
    "onlyfans",
    "hentai",
    "ecchi",
    "jav",
    "javhd",
    "sexo",
    "sexe",
    "milf",
    "nudes",
}

ADULT_RTA_PATTERNS = [
    r"rta[-\s]?50[0-9]",
    r"rta[-\s]?8067",
    r"xxx[-.]?18",
]

NON_LATIN_ADULT_TERMS = {
    "エッチ",
    "えっち",
    "ヘンタイ",
    "色情",
    "毛片",
    "성인",
    "야동",
}

TRAILING_PUNCTUATION = ".,;:!?)\"'>]}-"


def _strip_trailing_punctuation(url: str) -> str:
    return url.rstrip(TRAILING_PUNCTUATION)


def _canonical(url: str) -> str:
    lowered = url.lower().rstrip("/")

    if lowered.startswith("http://"):
        lowered = lowered[7:]
    elif lowered.startswith("https://"):
        lowered = lowered[8:]

    if lowered.startswith("www."):
        lowered = lowered[4:]

    return lowered


def find_urls(text: str) -> list[str]:
    """Comprehensive URL extraction: schemes, www, bare domains."""
    if not text:
        return []

    found = []
    seen = set()

    def add(url: str) -> None:
        key = _canonical(url)

        if key and key not in seen:
            seen.add(key)
            found.append(url)

    for match in URL_PATTERN.finditer(text):
        url = _strip_trailing_punctuation(match.group(0))

        if url:
            add(url)

    for match in BARE_DOMAIN_PATTERN.finditer(text):
        url = _strip_trailing_punctuation(match.group(0))

        if url:
            add(url)

    return found


def find_links(text: str) -> list[str]:
    """Backward-compatible alias of find_urls."""
    return find_urls(text)

MAX_BARE_DOMAIN_EXAMPLES = {"example.com", "github.com", "google.com"}

def extract_domain(url: str) -> str:
    if url.startswith("http://") or url.startswith("https://"):
        return urlparse(url).netloc.lower()

    netloc = url.split("/", 1)[0].lower()

    if netloc.startswith("www."):
        netloc = netloc[4:]

    return netloc


def _host_is_ip(domain: str) -> bool:
    if IP_PATTERN.match(domain):
        return True

    try:
        ipaddress.ip_address(domain)
        return True
    except ValueError:
        return False


def _punycode(domain: str) -> bool:
    return "xn--" in domain.lower()


def _tld(domain: str) -> str:
    parts = domain.split(".")

    return parts[-1].lower() if len(parts) > 1 else ""


def _lookalike_domain(domain: str, url: str) -> bool:
    lowered = (domain + url).lower()

    for brand in LOOKALIKE_KEYWORDS:
        if brand in lowered:
            return True

    return False


def _has_credential_path(path: str) -> bool:
    path = path.lower()

    for candidate in CREDENTIAL_PATHS:
        if candidate in path:
            return True

    return False


def _has_payment_signal(url: str) -> bool:
    lowered = url.lower()

    return any(keyword in lowered for keyword in PAYMENT_KEYWORDS)


def _has_phishing_signal(url: str) -> bool:
    lowered = url.lower()

    return any(keyword in lowered for keyword in PHISHING_KEYWORDS)


def _suspicious_parameters(url: str) -> bool:
    lowered = url.lower()

    for name in ("redirect", "url=", "to=", "dest=", "linker=", "adurl="):
        if name in lowered:
            return True

    return False


def _is_adult_domain(domain: str) -> bool:
    lowered = domain.lower()

    for suffix in ADULT_DOMAIN_SUFFIXES:
        if lowered == suffix or lowered.endswith("." + suffix):
            return True

    return False


def _has_adult_keyword(url: str) -> bool:
    lowered = url.lower()

    if any(re.search(pattern, lowered) for pattern in ADULT_RTA_PATTERNS):
        return True

    tokens = set(re.findall(r"[a-z0-9]+", lowered))

    if tokens & ADULT_KEYWORD_TOKENS:
        return True

    flattened = "".join(
        char
        for char in unicodedata.normalize("NFD", lowered)
        if not unicodedata.combining(char)
    )

    return any(term.lower() in flattened for term in NON_LATIN_ADULT_TERMS)


def analyze_url(url: str) -> dict:
    """Rich deterministic analysis. Classification defaults to UNKNOWN and is
    never escalated to DANGEROUS on unfamiliarity alone."""
    domain = extract_domain(url)
    parsed = urlparse(url)
    risk = 0
    reasons = []
    flags = []

    if _host_is_ip(domain):
        risk += 2
        reasons.append("IP address used as domain")
        flags.append("ip_host")

    normalized_domain = domain.lower()

    if normalized_domain in SHORTENERS:
        risk += 1
        reasons.append("URL shortener")
        flags.append("shortener")

    for redirector in REDIRECTORS:
        if f"/{redirector}" in parsed.path.lower():
            risk += 1
            reasons.append(f"redirector path /{redirector}")
            flags.append("redirector")
            break

    if _punycode(normalized_domain):
        risk += 2
        reasons.append("punycode domain")
        flags.append("punycode")

    if len(domain) > 40:
        risk += 1
        reasons.append("unusually long domain")
        flags.append("long_domain")

    tld = _tld(normalized_domain)

    if tld in SUSPICIOUS_TLDS:
        risk += 1
        reasons.append(f"suspicious TLD .{tld}")
        flags.append("suspicious_tld")

    if _has_credential_path(parsed.path):
        risk += 2
        reasons.append("credential/account path")
        flags.append("credential_path")

    if _has_payment_signal(url):
        risk += 1
        reasons.append("payment-related signal")
        flags.append("payment_signal")

    if _has_phishing_signal(url):
        risk += 2
        reasons.append("phishing keywords")
        flags.append("phishing_signal")

    if _suspicious_parameters(url):
        risk += 1
        reasons.append("suspicious redirect parameters")
        flags.append("redirect_params")

    if _lookalike_domain(normalized_domain, parsed.path):
        risk += 1
        reasons.append("possible lookalike domain")
        flags.append("lookalike")

    if _is_adult_domain(normalized_domain):
        risk += 3
        reasons.append("adult/18+ domain")
        flags.append("adult_domain")
    elif _tld(normalized_domain) in ADULT_TLDS:
        risk += 3
        reasons.append("adult TLD (.xxx)")
        flags.append("adult_domain")
    elif _has_adult_keyword(url):
        risk += 3
        reasons.append("adult/18+ keyword signal")
        flags.append("adult_keyword")

    return {
        "url": url,
        "domain": domain,
        "risk": risk,
        "reasons": reasons,
        "flags": flags,
    }


def classify_url(url: str) -> dict:
    result = analyze_url(url)

    domain = result["domain"].lower()

    if "adult_domain" in result["flags"] or "adult_keyword" in result["flags"]:
        result["classification"] = "ADULT"
        return result

    if domain in ("google.com", "github.com", "youtube.com") or is_trusted_domain(domain):
        result["classification"] = "SAFE"
        return result

    risk = result["risk"]

    dangerous = (
        ("ip_host" in result["flags"] and (
            "credential_path" in result["flags"]
            or "phishing_signal" in result["flags"]
        ))
        or ("punycode" in result["flags"] and (
            "lookalike" in result["flags"]
            or "credential_path" in result["flags"]
        ))
        or ("suspicious_tld" in result["flags"] and (
            "credential_path" in result["flags"]
            or "phishing_signal" in result["flags"]
        )))

    if dangerous:
        result["classification"] = "DANGEROUS"
    elif risk > 0:
        result["classification"] = "SUSPICIOUS"
    else:
        result["classification"] = "UNKNOWN"

    return result
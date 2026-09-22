import re
import unicodedata


def _flatten_marks(text: str) -> str:
    """NFD-decompose and drop combining marks so `\b` works on Tamil,
    Hindi, Sinhala matras and accented Latin (e.g. imbecil/imbécil)."""
    decomposed = unicodedata.normalize("NFD", text.lower())

    return "".join(
        char for char in decomposed if not unicodedata.combining(char)
    )


TOXIC_TERMS = {
    "stupid",
    "idiot",
    "moron",
    "dumb",
    "ugly",
    "loser",
    "pathetic",
    "worthless",
    "fool",
    "nutcase",
    "freak",
}

PROFANITY = {
    "shit",
    "bullshit",
    "shitty",
    "fuck",
    "fucked",
    "fucking",
    "fucker",
    "motherfucker",
    "bitch",
    "bastard",
    "dick",
    "prick",
    "cunt",
    "asshole",
    "jackass",
    "dumbass",
    "douchebag",
    "twat",
    "wanker",
    "bollocks",
    "crap",
    "damn",
    "goddamn",
    "hell",
    "piss",
}

SLURS = {
    "retard",
    "tranny",
}

MULTILINGUAL_PROFANITY = {
    "si": {
        "කෙස්ස",
        "ජරාව",
        "ජරා",
        "මෝඩ",
        "මෝඩයා",
        "බූරු",
        "බූරුවා",
        "පිස්සා",
        "පිස්සු",
        "මන්දා",
        "බල්ලා",
        "බල්ලෙක්",
        "බලු",
        "කැත",
        "කෙළවෙනෝ",
        "කෙලවෙනෝ",
        "ගොං",
        "කුණ්ඩ",
        "modaya",
        "moda",
        "pissa",
        "pissu",
        "jarawa",
        "kessa",
        "buruwa",
        "buru",
        "mandaya",
        "thamba",
        "tamba",
        "kelevano",
        "kelewano",
        "kelewanu",
        "kelawwa",
    },
    "ta": {
        "முட்டாள்",
        "கழுதை",
        "பாவி",
        "திமிர்",
        "கிறாக்கி",
        "போக்கிரி",
        "மண்டை",
        "மாங்கு",
        "muttal",
        "kazhudai",
        "kiraaki",
        "punda",
        "otha",
        "kundu",
        "thevidiya",
        "mosam",
    },
    "ar": {
        "خراء",
        "غبي",
        "أحمق",
        "احمق",
        "حمار",
        "معتوه",
        "زبالة",
        "كلب",
        "عاهرة",
        "شرموطة",
        "قحبة",
        "خول",
        "حمير",
    },
    "es": {
        "puta",
        "puto",
        "pendejo",
        "cabrón",
        "cabron",
        "jódete",
        "jodete",
        "imbécil",
        "imbecil",
        "estúpido",
        "estupido",
        "mierda",
        "mamón",
        "mamon",
        "zorra",
        "polla",
        "maricón",
        "maricon",
        "subnormal",
        "malparido",
    },
    "fr": {
        "putain",
        "merde",
        "connard",
        "conasse",
        "salope",
        "enculé",
        "encule",
        "abruti",
        "fils de pute",
    },
    "pt": {
        "merda",
        "porra",
        "caralho",
        "idiota",
        "imbecil",
        "puta",
        "babaca",
        "otário",
        "otario",
        "arrombado",
        "vadia",
        "vagabunda",
        "filho da puta",
    },
    "hi": {
        "मूर्ख",
        "गध",
        "कुतिया",
        "बकवास",
        "चूतिया",
        "मादरचोद",
        "भोसड़ी",
        "भोसडीके",
        "बहनचोद",
        "गांड",
        "लौड़े",
        "मुर्ख",
        "chutiya",
        "chutiyapa",
        "madarchod",
        "bhenchod",
        "behenchod",
        "gandu",
        "gaandu",
        "bhosdike",
        "lode",
        "laude",
        "kamina",
        "harami",
        "murkh",
        "bakwas",
        "gadha",
    },
    "fil": {
        "bobo",
        "tanga",
        "gago",
        "ulol",
        "lintik",
        "putang",
        "tarantado",
        "hayop",
        "buwisit",
    },
    "id": {
        "bangsat",
        "anjing",
        "goblok",
        "bodoh",
        "bacot",
        "jembut",
        "kontol",
        "memek",
    },
    "sw": {
        "mjinga",
        "mnyama",
        "punda",
        "gimu",
        "shetani",
        "kinywa",
        "mlenda",
    },
    "bn": {
        "বোকা",
        "গাধা",
        "হরামি",
        "চোদা",
        "মাদারচোদ",
        "বেশ্যা",
        "bokachoda",
    },
    "ur": {
        "بیوقوف",
        "گدھا",
        "حرامی",
        "بکواس",
        "کمینہ",
        "کسی",
        "bewaqoof",
        "harami",
        "kameena",
    },
    "vi": {
        "đỉ",
        "đĩ",
        "khốn",
        "ngu",
        "mẹ mày",
        "cái lồn",
        "đồ ngu",
    },
}

ABUSE_PHRASES = {
    "shut up",
    "shut your mouth",
    "go away",
    "you are useless",
    "you are trash",
    "get lost",
    "bug off",
}

HARASSMENT_PATTERNS = [
    (r"\byou\s+(?:are|were|will\s+always?)\s+(?:a?\s*)?(?:stupid|pathetic|loser|trash|useless|worthless)\b", 2),
    (r"\byour\s+(?:mother|family|face|whole\s+family)\b", 2),
    (r"\bnobody\s+(?:likes|loves|wants)\s+you\b", 2),
    (r"\bkick\s+(?:him|her|them)\s+out\b", 1),
]

THREAT_PATTERNS = [
    (r"\bi\s+(?:will|'ll|am\s+going\s+to)\b.*\b(?:kill|beat|hurt|shoot|harm|destroy|smash|attack)\s+you\b", 3),
    (r"\bi\s+(?:will|'ll|am\s+going\s+to)\b.*\b(?:kill|hurt|harm|attack)\b.*\b(?:your\s+family|your\s+kids|your\s+mother)\b", 3),
    (r"\byou\s+better\s+(?:watch\s+out|run|hide)\b", 2),
    (r"\b(?:watch|careful)\b.*\b(?:behind\s+you|your\s+back)\b", 2),
]

SELF_HARM_PATTERNS = {
    "kill myself",
    "end it all",
    "want to die",
    "self harm",
    "self-harm",
}

WORD_BOUNDARY = re.compile(r"\b([a-z]+)\b")


def _contains_term(low: str, term: str) -> bool:
    if " " in term:
        return term in low

    return WORD_BOUNDARY.search(low) is not None and term in low


def _contains_word(low: str, term: str) -> bool:
    """Language-aware match for a term.

    ASCII terms use whole-word matching (avoids 'hell' inside 'hello',
    'ass' inside 'class'). Non-ASCII scripts use substring matching because
    they are heavily inflected (Sinhala moḋayek, Hindi gadhe) and `\b` is
    unreliable. Both sides are NFD-flattened so combining marks do not break
    boundaries (Tamil/Hindi/Sinhala matras, accented Latin).
    """
    plain_text = _flatten_marks(low)
    plain_term = _flatten_marks(term)

    if any(ord(char) > 127 for char in plain_term):
        return plain_term in plain_text

    return re.search(r"\b" + re.escape(plain_term) + r"\b", plain_text) is not None


def detect_toxicity(text: str) -> dict:
    if not text:
        return {"risk": 0, "reasons": [], "categories": []}

    low = text.lower()
    categories = []
    reasons = []
    risk = 0

    self_harm = any(p in low for p in SELF_HARM_PATTERNS)

    threat_risk_before = risk

    for pattern, weight in THREAT_PATTERNS:
        if re.search(pattern, low):
            risk += weight
            reasons.append("threat")
            break

    if self_harm:
        threat_flag = risk > threat_risk_before

        if threat_flag:
            risk -= 1

        reasons.append("self_harm_concern")
        categories.append("CONCERN")

    for term in TOXIC_TERMS:
        if _contains_term(low, term):
            risk += 1
            reasons.append(f"toxic:{term}")
            categories.append("TOXIC")
            break

    for term in PROFANITY:
        if _contains_word(low, term):
            risk += 1
            reasons.append(f"profanity:{term}")
            categories.append("TOXIC")
            break

    for language, terms in MULTILINGUAL_PROFANITY.items():
        for term in terms:
            if _contains_word(low, term):
                risk += 1
                reasons.append(f"profanity:{language}:{term}")
                categories.append("TOXIC")
                break

    for term in SLURS:
        if _contains_term(low, term):
            risk += 2
            reasons.append(f"slur:{term}")
            categories.append("TOXIC")
            break

    for phrase in ABUSE_PHRASES:
        if phrase in low:
            risk += 1
            reasons.append("verbal_abuse")
            categories.append("HARASSMENT")
            break

    for pattern, weight in HARASSMENT_PATTERNS:
        if re.search(pattern, low):
            risk += weight
            reasons.append("harassment")
            categories.append("HARASSMENT")
            break

    for flag in THREAT_PATTERNS:
        if re.search(flag[0], low):
            categories.append("THREAT")
            break

    return {
        "risk": min(risk, 10),
        "reasons": reasons,
        "categories": list(dict.fromkeys(categories)),
    }
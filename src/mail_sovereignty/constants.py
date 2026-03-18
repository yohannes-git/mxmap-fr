import re

MICROSOFT_KEYWORDS = [
    "mail.protection.outlook.com",
    "outlook.com",
    "microsoft",
    "office365",
    "onmicrosoft",
    "spf.protection.outlook.com",
    "sharepointonline",
]
GOOGLE_KEYWORDS = [
    "google",
    "googlemail",
    "gmail",
    "_spf.google.com",
    "aspmx.l.google.com",
]
AWS_KEYWORDS = ["amazonaws", "amazonses", "awsdns"]
OVH_KEYWORDS = ["ovh.net", "ovhcloud.com", "mx.ovh.com", "ovh.com"]
GANDI_KEYWORDS = ["gandi.net", "gandimail.net", "gandi.mail"]

# FAI français grand public — détectés sur le MX ou le domaine de l'email de contact
ORANGE_KEYWORDS = [
    "orange.fr", "orange.com",
    "wanadoo.fr", "wanadoo.com",
    "francetelecom.com",
    "cloudance.com",   # filiale messagerie Orange pro
]
FREE_KEYWORDS = [
    "free.fr",
    "aliceadsl.fr",
    "tiscali.fr",
    "iliad.fr",
    "proxad.net",      # infrastructure MX Free
    "dedibox.fr",
]
SFR_KEYWORDS = [
    "sfr.fr", "sfr.com", "sfr.net",
    "numericable.fr", "numericable.com",
    "cegetel.net",
    "club-internet.fr",
    "neuf.fr",
    "9online.fr",
    "completel.net",
]
BOUYGUES_KEYWORDS = [
    "bbox.fr",
    "bouyguestelecom.fr",
    "bouygtel.com",
]

PROVIDER_KEYWORDS = {
    "microsoft": MICROSOFT_KEYWORDS,
    "google": GOOGLE_KEYWORDS,
    "aws": AWS_KEYWORDS,
    "ovh": OVH_KEYWORDS,
    "gandi": GANDI_KEYWORDS,
    "orange": ORANGE_KEYWORDS,
    "free": FREE_KEYWORDS,
    "sfr": SFR_KEYWORDS,
    "bouygues": BOUYGUES_KEYWORDS,
}

FOREIGN_SENDER_KEYWORDS = {
    "mailchimp": ["mandrillapp.com", "mandrill", "mcsv.net"],
    "sendgrid": ["sendgrid"],
    "mailjet": ["mailjet"],
    "mailgun": ["mailgun"],
    "brevo": ["sendinblue", "brevo"],
    "mailchannels": ["mailchannels"],
    "smtp2go": ["smtp2go"],
    "nl2go": ["nl2go"],
    "hubspot": ["hubspotemail"],
    "knowbe4": ["knowbe4"],
    "hornetsecurity": ["hornetsecurity", "hornetdmarc"],
}

SPARQL_URL = "https://query.wikidata.org/sparql"

SPARQL_QUERY = """
SELECT ?commune ?communeLabel ?insee ?website ?departementLabel ?regionLabel WHERE {
  ?commune wdt:P31 wd:Q484170 .          # instance of: commune de France
  ?commune wdt:P374 ?insee .             # code INSEE
  FILTER NOT EXISTS {                     # exclure les communes dissoutes
    ?commune wdt:P576 ?dissolved .
    FILTER(?dissolved <= NOW())
  }
  FILTER NOT EXISTS {                     # exclure les communes avec P31 terminé
    ?commune p:P31 ?stmt .
    ?stmt ps:P31 wd:Q484170 .
    ?stmt pq:P582 ?endTime .
    FILTER(?endTime <= NOW())
  }
  FILTER NOT EXISTS {                     # exclure les communes fusionnées
    ?commune wdt:P1366 ?successor .
  }
  OPTIONAL { ?commune wdt:P856 ?website . }
  OPTIONAL {
    ?commune wdt:P131 ?departement .
    ?departement wdt:P31/wdt:P279* wd:Q6465 .   # instance of département français
    OPTIONAL {
      ?departement wdt:P131 ?region .
      ?region wdt:P31 wd:Q36784 .               # instance of région française
    }
  }
  SERVICE wikibase:label { bd:serviceParam wikibase:language "fr,en" . }
}
ORDER BY ?insee
"""

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
TYPO3_RE = re.compile(r"linkTo_UnCryptMailto\(['\"]([^'\"]+)['\"]")

SKIP_DOMAINS = {
    "example.com",
    "example.fr",
    "sentry.io",
    "w3.org",
    "gstatic.com",
    "googleapis.com",
    "schema.org",
}

SUBPAGES = [
    "/contact",
    "/contact/",
    "/nous-contacter",
    "/nous-contacter/",
    "/mairie",
    "/mairie/",
    "/administration",
    "/administration/",
    "/accueil",
    "/mentions-legales",
    "/mentions-legales/",
    "/la-mairie",
    "/la-mairie/contact",
    # Conservé pour les communes bilingues (Alsace, Moselle, etc.)
    "/kontakt",
    "/impressum",
]

GATEWAY_KEYWORDS = {
    "barracuda": ["barracudanetworks.com", "barracuda.com"],
    "trendmicro": ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com"],
    "proofpoint": ["ppe-hosted.com"],
    "sophos": ["hydra.sophos.com"],
    "mimecast": ["mimecast.com"],
    "vaderetro": ["vaderetro.com", "vade-retro.com"],  # acteur français
}

# ASNs d'hébergeurs et FAI français notables
FRENCH_ISP_ASNS: dict[int, str] = {
    2200: "RENATER",
    5410: "Bouygues Telecom",
    5511: "Orange",
    8075: "Microsoft",           # présent en France aussi
    12322: "Free / Iliad",
    13193: "Celeste",
    15557: "SFR",
    16347: "Ikoula",
    20766: "Gitoyen",
    21502: "Numericable",
    24904: "Kwaoo / Alsatis",
    29075: "IELO-LIAZO",
    34019: "Hivane",
    34177: "Celeste",
    35189: "OVHcloud",
    36408: "Medianova",
    43100: "Leonix Telecom",
    197133: "Infomaniak (FR)",
}

CONCURRENCY = 20
CONCURRENCY_POSTPROCESS = 10
CONCURRENCY_SMTP = 50  # port 25 TCP only, pas de gros transfert — on peut paralleliser largement

SMTP_BANNER_KEYWORDS = {
    "microsoft": [
        "microsoft esmtp mail service",
        "outlook.com",
        "protection.outlook.com",
    ],
    "google": [
        "mx.google.com",
        "google esmtp",
    ],
    "ovh": [
        "ovh.net",
        "ovhcloud.com",
    ],
    "gandi": [
        "gandi.net",
        "gandimail.net",
    ],
    "aws": [
        "amazonaws",
        "amazonses",
    ],
}

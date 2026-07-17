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
IONOS_KEYWORDS = [
    "ionos.fr", "ionos.com", "ionos.de",
    "1and1.com", "1and1.fr", "schlund.de",
    "ui-portal.de",   # infrastructure IONOS
    "1and1.net",
]
INFOMANIAK_KEYWORDS = [
    "infomaniak.com", "infomaniak.ch",
    "mta-gw.infomaniak.ch", "mxpool.infomaniak.com",
    "ikmail.com",
]
VADESECURE_KEYWORDS = [
    "vadesecure.com", "vaderetro.com", "vade-retro.com",
    "vade.com",
]
# BlueMind : serveur mail français open-source (concurrent de Zimbra)
# Apparaît dans les MX (bluemind.ideal360.fr) ou via scan webmail HTTP
# ags-cloud.fr : hébergeur BlueMind exclusif pour les collectivités françaises
BLUEMIND_KEYWORDS = [
    "bluemind",      # sous-domaine ou nom d'hôte contenant "bluemind"
    "blue-mind",     # variante avec tiret
    "ags-cloud.fr",  # AGS Cloud - hébergeur BlueMind pour collectivités (Bretagne, etc.)
]

# Zimbra : serveur mail open-source auto-hébergé
# Apparaît dans les MX (zimbra.maville.fr) ou dans les SPF (a:zimbra-prod.alpi40.fr)
ZIMBRA_KEYWORDS = [
    "zimbra",        # sous-domaine ou nom d'hôte contenant "zimbra"
    "alpi40.fr",     # hébergeur Zimbra régional (Alpes)
    "zcs.",          # Zimbra Collaboration Suite
    "zimbramail",
]

# Exchange On-Premise : serveur Exchange hébergé localement
# Détecté via OWA sur le domaine de la commune (pas sur outlook.com)
# Le provider devient "exchange" au lieu de "microsoft"
EXCHANGE_OWA_SIGNATURES = [
    "owa", "owauth", "exchange", "outlook web app",
    "x-owa-version", "x-ms-diagnostics",
]

# Webmails détectables via HTTP
WEBMAIL_APPS = {
    "owa":        ["owa", "outlook web app", "x-owa-version", "/owa/auth"],
    "zimbra":     ["zimbra", "zcs", "zimbramail"],
    "bluemind":   ["bluemind", "blue-mind"],
    "roundcube":  ["roundcube", "static/login", "rcube"],
    "sogo":       ["sogo", "/SOGo"],
    "rainloop":   ["rainloop", "snappymail"],
    "horde":      ["horde", "imp/login"],
    "mailo":      ["mailo.com"],
    "afterlogic": ["afterlogic"],
    "icewarp":    ["icewarp", "merak"],
    "kerio":      ["kerio"],
    "open-xchange": ["appsuite", "open-xchange"],
}
WEBMAIL_PROBES: list[tuple[str, str | None]] = [
    ("/owa",                "microsoft"),  # OWA Exchange on-prem
    ("/owa/auth/logon.aspx","microsoft"),
    ("/zimbra",             "zimbra"),
    ("/bluemind",           "bluemind"),
    ("/mail",               None),
    ("/webmail",            None),
    ("/roundcube",          "local"),
    ("/roundcubemail",      "local"),
]

YAHOO_KEYWORDS = [
    "yahoo.fr", "yahoo.com", "yahoo.net",
    "yahoodns.net",          # MX infrastructure Yahoo
    "ymail.com",
]

# FAI français grand public - détectés sur le MX ou le domaine de l'email de contact
ORANGE_KEYWORDS = [
    # Orange actuel
    "orange.fr", "orange.com",
    # Wanadoo (filiale historique France Télécom → Orange)
    "wanadoo.fr", "wanadoo.com",
    # France Télécom
    "francetelecom.com", "francetelecom.fr",
    # Voilà (portail FT années 2000)
    "voila.fr",
    # Clubic / Club Internet (racheté par Orange)
    "club-internet.fr",
]
FREE_KEYWORDS = [
    # Free / Iliad actuel
    "free.fr", "freebox.fr",
    # Alice (racheté par Free en 2008)
    "aliceadsl.fr", "alice.fr",
    # Tiscali France (racheté par Alice)
    "tiscali.fr",
    # Infonie (historique, racheté par Tiscali)
    "infonie.fr",
    # Infrastructure MX Free / Iliad
    "proxad.net", "iliad.fr",
    # Dedibox / Online.net (groupe Iliad)
    "dedibox.fr", "online.net",
]
SFR_KEYWORDS = [
    # SFR actuel
    "sfr.fr", "sfr.com", "sfr.net",
    # Numericable (fusionné SFR 2014)
    "numericable.fr", "numericable.com",
    "noos.fr",                       # câblo-opérateur racheté par Numericable
    "numericable-caraibes.fr",
    "sequalum.net",
    # Neuf Cegetel (racheté par SFR 2008)
    "neuf.fr", "neuf.com",
    "cegetel.net",
    "9online.fr", "9business.fr",
    # Cario, Guidéo, Magéos (rachetés par Neuf)
    "cario.fr", "guideo.fr", "mageos.com",
    # Fnac.net (portail FAI FNAC → Magéos → SFR)
    "fnac.net",
    # Waika9 / 9Télécom (racheté par Neuf)
    "waika9.com",
    # Autres domaines SFR historiques
    "akeonet.com", "evc.net", "evhr.net",
    "modulonet.fr", "netspeed.fr",
    "tv-com.net", "valvision.fr",
    "club.fr",
]
BOUYGUES_KEYWORDS = [
    # Bouygues Telecom actuel
    "bbox.fr", "bbox.bouyguestelecom.fr",
    "bouyguestelecom.fr", "bouygtel.com",
    # Darty Box (partenariat Bouygues)
    "dartybox.com",
]

PROVIDER_KEYWORDS = {
    "microsoft": MICROSOFT_KEYWORDS,
    "google": GOOGLE_KEYWORDS,
    "aws": AWS_KEYWORDS,
    "ovh": OVH_KEYWORDS,
    "gandi": GANDI_KEYWORDS,
    "ionos": IONOS_KEYWORDS,
    "infomaniak": INFOMANIAK_KEYWORDS,
    "vadesecure": VADESECURE_KEYWORDS,
    "bluemind": BLUEMIND_KEYWORDS,
    "zimbra": ZIMBRA_KEYWORDS,
    "yahoo": YAHOO_KEYWORDS,
    "orange": ORANGE_KEYWORDS,
    "free": FREE_KEYWORDS,
    "sfr": SFR_KEYWORDS,
    "bouygues": BOUYGUES_KEYWORDS,
}

# Domaines "hébergement local / fédéré" - domaines propres à la mairie
# ou hébergeurs associatifs/coopératifs français
# Ce ne sont pas des keywords à détecter, c'est la catégorie par défaut
# quand le domaine est .fr et n'appartient à aucun FAI/cloud connu
LOCAL_TLD_SUFFIXES = [".fr", ".bzh", ".alsace", ".paris", ".corsica"]

# Providers dont l'infrastructure mail est hébergée hors UE (cloud US notamment).
# "exchange" est exclu : c'est un serveur on-prem, donc hébergé localement en France
# même si le logiciel est édité par Microsoft.
NON_EU_CLOUD_PROVIDERS = {"microsoft", "google", "aws", "yahoo"}

# Gateways de GATEWAY_KEYWORDS dont la société éditrice est hors UE (siège et/ou
# filiale soumise au CLOUD Act US, ou UK post-Brexit). Le gateway voit passer le
# contenu des emails (filtrage anti-spam/anti-virus) : sa juridiction compte pour
# la souveraineté même quand le provider final derrière lui est "unknown" (cf.
# classify.py - un gateway sans hébergeur identifiable derrière retombe sur
# provider="unknown", donc classify_sovereignty() doit aussi regarder `gateway`).
# barracuda (US, Californie), proofpoint (US, Californie), cisco (US, Californie),
# fortinet (US, Californie), sophos (UK, hors UE), trendmicro (Japon), mimecast
# (UK + filiale US) : non_eu. vadesecure/altospam/mailinblack/layer (France) et
# hornetsecurity (Allemagne) restent EU. "mailcontrol" : origine incertaine, pas
# inclus faute de confiance suffisante sur la juridiction.
NON_EU_GATEWAYS = {
    "barracuda", "proofpoint", "cisco", "fortinet", "sophos", "trendmicro", "mimecast",
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
    "barracuda":      ["barracudanetworks.com", "barracuda.com"],
    "trendmicro":     ["tmes.trendmicro.eu", "tmes.trendmicro.com"],
    "hornetsecurity": ["hornetsecurity.com"],
    "proofpoint":     ["ppe-hosted.com"],
    "sophos":         ["hydra.sophos.com"],
    "mimecast":       ["mimecast.com"],
    "vadesecure":     ["vadesecure.com", "vaderetro.com", "vade-retro.com"],
    "cisco":          ["iphmx.com", "ironport.com", "ciscoemail.com"],
    "altospam":       ["altospam.com", "altospam.net"],
    "cleanmail":      ["clean-mailbox.com", "cleanmail.eu"],
    "fortinet":       ["fortimailcloud.com"],
    "mailcontrol":    ["mailcontrol.com"],
    "mailinblack":    ["mailinblack.com"],   # gateway anti-spam français
    "layer":          ["layer.fr"],              # relais/hébergeur français
}

# Hébergeurs français régionaux - classifiés "independent" (prestataire local)
# Utilisés comme MX par les communes, pas des gateways de filtrage
FRENCH_REGIONAL_HOSTERS = [
    # Hébergeurs mutualisés / revendeurs
    "inforoutes.fr",       # réseau départemental Ain
    "numerian.fr",         # hébergeur Ardèche
    "xefi.fr",             # XEFI IT services
    "securemail.pro",      # prestataire sécurité mail
    "stelogy.net",         # hébergeur régional
    "as8677.net",          # AS8677 réseau Bourgogne
    "security-mail.net",   # prestataire sécurité
    "lerelaisinternet.com",# hébergeur régional
    "mailo.com",           # Mailo - messagerie française
    "o2switch.net",        # O2switch hébergeur français
    "illicoweb.com",       # hébergeur Alsace
    "yulpa.io",            # hébergeur français
    "amediasolutions.fr",  # prestataire Corrèze
    "manche.io",           # réseau Manche
    "shd-cloud.fr",        # SHD Cloud Ain
    "ozone.net",           # hébergeur Ardennes
    "jimdo.com",           # plateforme site web (avec mail)
    "rvvn.org",            # réseau Aisne
    "coraxis.fr",          # hébergeur Alsace
    "bookmyname.com",      # registrar français
    "mct.eu",              # Maine Cloud Telecom
    "agc-tech.net",        # AGC Tech Alsace
    "sarthefibre.fr",      # Sarthe Fibre
    "creasrv.net",         # hébergeur Charente
    "recia.tech",          # RECIA Centre-Val de Loire
    "dataxy.fr",           # DataXY hébergeur
    "misesurorbite.net",   # hébergeur régional
    "artefact.fr",         # Artefact Corrèze
    "iptis.net",           # IPTIS Corrèze
    "vini.pf",             # Vini Polynésie française
    "global-sp.net",       # Global SP
    "absys-online.fr",     # Absys Hérault
    "vogamail.com",        # Voga Mail Auvergne
    "carboniocloud.fr",    # Carbonio (Zextras) cloud FR
    "ic2a.net",            # IC2A Tarn
    "altinea.fr",          # Altinea Franche-Comté
    "digital-max.fr",      # Digital Max Landes
    "digitalmax.fr",       # Digital Max Landes
    "serveursdns.net",     # hébergeur Alsace
    "powermail.fr",        # PowerMail FR
    "ags-hosting.fr",      # AGS Hosting
    "oci.fr",              # OCI hébergeur
    "egit.cloud",          # EGIT cloud Bretagne
    "egit2.cloud",         # EGIT cloud Bretagne
    "cc-sevreloire.fr",    # CC Sèvre et Loire
    "vialis.net",          # Vialis Alsace
    "alfaserv.pro",        # Alfa Serv Auvergne
    "eu.com",              # registrar européen
    "produhost.net",       # Produhost
    "planetb.fr",          # PlanetB Bourgogne
    "dri.fr",              # DRI hébergeur
    "euro-info.fr",        # Euro-Info Nord
    "my-cosi.info",        # My COSI
    "prosoluce.fr",        # Prosoluce Haute-Garonne
    "alwaysdata.com",      # Alwaysdata hébergeur FR
    "alwaysdata.net",      # Alwaysdata hébergeur FR
    "mybsuite.fr",         # MyBSuite Normandie
    "opalecenter.fr",      # Opale Center Nord
    "agilium-mail.fr",     # Agilium Mail Haute-Savoie
    "netim.net",           # Netim registrar FR
    "nordnet.fr",          # Nordnet hébergeur
    "hostinger.com",       # Hostinger
    "fibracom.fr",         # Fibracom Charente
    "qualite-info.fr",     # Qualité Info Bretagne
    "brest-metropole.fr",  # Brest Métropole
    "alinto.net",          # Alinto messagerie FR
    "eolas.fr",            # Eolas Isère
    "gmx.net",             # GMX (web.de)
    "cmc.bzh",             # CMC Bretagne
    "prolan.pf",           # Prolan Polynésie
    "laposte.net",         # La Poste Pro - email mutualisé pour collectivités
    "lpn.as8677.net",      # Infrastructure MX La Poste
]

# Domaines mutualisés connus : jamais de l'auto-hébergement communal
# Utilisé dans postprocess pour exclure la sonde webmail sur ces domaines
SHARED_EMAIL_DOMAINS = {
    "laposte.net",
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.fr",
    "yahoo.com",
    "orange.fr",
    "wanadoo.fr",
    "free.fr",
    "sfr.fr",
    "numericable.fr",
    "bbox.fr",
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

CONCURRENCY = 100          # DNS = UDP léger, on peut paralléliser largement
CONCURRENCY_HTTP = 30      # HTTP probe webmail : I/O réseau plus lourd que DNS
CONCURRENCY_POSTPROCESS = 20
CONCURRENCY_SMTP = 50  # port 25 TCP only, pas de gros transfert - on peut paralleliser largement

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
    "infomaniak": [
        "infomaniak.com",
        "infomaniak.ch",
    ],
    "vadesecure": [
        "vadesecure.com",
        "vaderetro.com",
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

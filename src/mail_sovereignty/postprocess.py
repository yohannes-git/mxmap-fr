import asyncio
import csv
import io
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS')

from mail_sovereignty.classify import (
    classify,
    classify_from_smtp_banner,
    classify_sovereignty,
    detect_gateway,
)
from mail_sovereignty.constants import (
    CONCURRENCY_POSTPROCESS,
    CONCURRENCY_SMTP,
    EMAIL_RE,
    GATEWAY_KEYWORDS,
    SKIP_DOMAINS,
    SHARED_EMAIL_DOMAINS,
    SUBPAGES,
    TYPO3_RE,
)
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)
from mail_sovereignty.smtp import fetch_smtp_banner


# Code Officiel Geographique (INSEE) - liste des communes/communes deleguees/
# communes associees. Sert uniquement a identifier les codes INSEE "COMD"/"COMA"
# (communes deleguees suite a une fusion) et leur commune de rattachement
# (COMPARENT), pour ne pas dupliquer une meme commune nouvelle sous deux codes
# INSEE dans data.json. Millesime a mettre a jour ponctuellement (~1x/an,
# nouvelles fusions de communes au 1er janvier) - voir data.gouv.fr "Code
# officiel geographique (COG)" pour le fichier vXXXX le plus recent.
COG_CSV_URL = "https://www.insee.fr/fr/statistiques/fichier/8740222/v_commune_2026.csv"
COG_CACHE_PATH = Path(".cog_cache.csv")
COG_CACHE_MAX_AGE_HOURS = 24 * 30


async def _fetch_cog_csv(client: httpx.AsyncClient) -> str:
    """Telecharge (ou reutilise le cache local) la table COG des communes."""
    if COG_CACHE_PATH.exists():
        age_hours = (time.time() - COG_CACHE_PATH.stat().st_mtime) / 3600
        if age_hours < COG_CACHE_MAX_AGE_HOURS:
            return COG_CACHE_PATH.read_text(encoding="utf-8")
    r = await client.get(COG_CSV_URL, timeout=30)
    r.raise_for_status()
    COG_CACHE_PATH.write_text(r.text, encoding="utf-8")
    return r.text


def _parse_deleguee_parents(csv_text: str) -> dict[str, str]:
    """Retourne {insee_commune_deleguee: insee_commune_de_rattachement}."""
    reader = csv.DictReader(io.StringIO(csv_text))
    return {
        row["COM"]: row["COMPARENT"]
        for row in reader
        if row["TYPECOM"] in ("COMD", "COMA") and row.get("COMPARENT")
    }


def decrypt_typo3(encoded: str, offset: int = 2) -> str:
    """Decrypt TYPO3 linkTo_UnCryptMailto Caesar cipher.

    TYPO3 encrypts mailto: links with a Caesar shift on three ASCII ranges:
      0x2B-0x3A (+,-./0123456789:)  -- covers . : and digits
      0x40-0x5A (@A-Z)             -- covers @ and uppercase
      0x61-0x7A (a-z)             -- covers lowercase
    Default encryption offset is -2, so decryption is +2 with wrap.
    """
    ranges = [(0x2B, 0x3A), (0x40, 0x5A), (0x61, 0x7A)]
    result = []
    for c in encoded:
        code = ord(c)
        decrypted = False
        for start, end in ranges:
            if start <= code <= end:
                n = code + offset
                if n > end:
                    n = start + (n - end - 1)
                result.append(chr(n))
                decrypted = True
                break
        if not decrypted:
            result.append(c)
    return "".join(result)


def extract_email_domains(html: str) -> set[str]:
    """Extract email domains from HTML, including TYPO3-obfuscated emails."""
    domains = set()

    for email in EMAIL_RE.findall(html):
        domain = email.split("@")[1].lower()
        if domain not in SKIP_DOMAINS:
            domains.add(domain)

    for email in __import__("re").findall(r'mailto:([^">\s?]+)', html):
        if "@" in email:
            domain = email.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    for encoded in TYPO3_RE.findall(html):
        decoded = decrypt_typo3(encoded)
        decoded = decoded.replace("mailto:", "")
        if "@" in decoded:
            domain = decoded.split("@")[1].lower()
            if domain not in SKIP_DOMAINS:
                domains.add(domain)

    return domains


def build_urls(domain: str) -> list[str]:
    """Build candidate URLs to scrape, trying www. prefix first."""
    domain = domain.strip()
    if domain.startswith(("http://", "https://")):
        parsed = urlparse(domain)
        domain = parsed.hostname or domain
    if domain.startswith("www."):
        bare = domain[4:]
    else:
        bare = domain

    bases = [f"https://www.{bare}", f"https://{bare}"]
    urls = []
    for base in bases:
        urls.append(base + "/")
        for path in SUBPAGES:
            urls.append(base + path)
    return urls


async def scrape_email_domains(client: httpx.AsyncClient, domain: str) -> set[str]:
    """Scrape a commune website for email domains."""
    if not domain:
        return set()

    all_domains = set()
    urls = build_urls(domain)

    for url in urls:
        try:
            r = await client.get(url, follow_redirects=True, timeout=15)
            if r.status_code != 200:
                continue
            domains = extract_email_domains(r.text)
            all_domains |= domains
            if all_domains:
                return all_domains
        except Exception:
            continue

    return all_domains


async def process_unknown(
    client: httpx.AsyncClient, semaphore: asyncio.Semaphore, m: dict[str, Any]
) -> dict[str, Any]:
    """Try to resolve an unknown commune by scraping its website."""
    async with semaphore:
        insee = m["insee"]
        name = m["name"]
        domain = m.get("domain", "")

        if not domain:
            print(f"  SKIP     {insee:>6} {name:<30} (no domain)")
            return m

        email_domains = await scrape_email_domains(client, domain)

        for email_domain in sorted(email_domains):
            mx = await lookup_mx(email_domain)
            if mx:
                spf = await lookup_spf(email_domain)
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                autodiscover = await lookup_autodiscover(email_domain)
                provider = classify(
                    mx,
                    spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                    autodiscover=autodiscover or None,
                )
                gateway = detect_gateway(mx)
                print(
                    f"  RESOLVED {insee:>6} {name:<30} "
                    f"email_domain={email_domain} -> {provider}"
                )
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                m["domain"] = email_domain
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                if autodiscover:
                    m["autodiscover"] = autodiscover
                m.pop("contact_email", None)  # ne pas publier
                return m

        print(
            f"  UNKNOWN  {insee:>6} {name:<30} "
            f"(scraped email domains: {email_domains or 'none'})"
        )
        return m


# Overrides manuels pour la France.
# Clé = code INSEE, valeur = champs à écraser.
# Cas typiques :
#   - commune absente de la DILA (communes nouvelles)
#   - domaine mutualisé à l'échelle d'un département / EPCI
#   - correction d'une mauvaise détection automatique
MANUAL_OVERRIDES: dict[str, dict[str, Any]] = {
    # Montaigu-Vendée (85146) : commune nouvelle, seule la mairie déléguée est dans la DILA
    # On écrase le nom, le domaine et on force le re-lookup DNS
    "85146": {
        "name": "Mairie - Montaigu-Vendée",
        "departement": "Vendée",
        "region": "Pays de la Loire",
        "domain": "montaigu-vendee.fr",
    },
    # Communes absentes de la DILA - pas de présence numérique connue
    # Villages morts pour la France (Verdun, WW1) - aucun habitant, pas d'email
    "55039": {"name": "Beaumont-en-Verdunois",       "departement": "Meuse",          "region": "Grand Est"},
    "55050": {"name": "Bezonvaux",                    "departement": "Meuse",          "region": "Grand Est"},
    "55139": {"name": "Cumières-le-Mort-Homme",       "departement": "Meuse",          "region": "Grand Est"},
    "55189": {"name": "Fleury-devant-Douaumont",      "departement": "Meuse",          "region": "Grand Est"},
    "55239": {"name": "Haumont-près-Samogneux",       "departement": "Meuse",          "region": "Grand Est"},
    "55307": {"name": "Louvemont-Côte-du-Poivre",     "departement": "Meuse",          "region": "Grand Est"},
    # La Pacaudière (42163) : DILA sans email ni site web
    # contact@lapacaudiere.fr → MX lapacaudiere-fr.mail.protection.outlook.com
    "42163": {
        "name": "Mairie - La Pacaudière",
        "departement": "Loire",
        "region": "Auvergne-Rhône-Alpes",
        "domain": "lapacaudiere.fr",
        "mx": ["lapacaudiere-fr.mail.protection.outlook.com"],
        "provider": "microsoft",
    },
    # Autres communes absentes de la DILA
    "25346": {"name": "Longeville",                   "departement": "Doubs",          "region": "Bourgogne-Franche-Comté"},
    "26015": {"name": "Aubenasson",                   "departement": "Drôme",          "region": "Auvergne-Rhône-Alpes"},
    "26080": {"name": "Chastel-Arnaud",               "departement": "Drôme",          "region": "Auvergne-Rhône-Alpes"},
    "59418": {"name": "Mortagne-du-Nord",             "departement": "Nord",           "region": "Hauts-de-France"},
    "62295": {"name": "Enquin-lez-Guinegatte",        "departement": "Pas-de-Calais",  "region": "Hauts-de-France"},
    # Orée d'Anjou (49126) : commune nouvelle absente de la DILA
    # MX webmail.oreedanjou.fr mais SPF contient spf.protection.outlook.com → Microsoft 365
    "49126": {
        "name": "Orée d'Anjou",
        "departement": "Maine-et-Loire",
        "region": "Pays de la Loire",
        "domain": "oreedanjou.fr",
        "mx": ["webmail.oreedanjou.fr"],
        "provider": "microsoft",
    },
    # Marseille (13055) : gateway Mimecast devant serveur propre (IPs fixes ville)
    "13055": {
        "name": "Mairie de Marseille",
        "departement": "Bouches-du-Rhône",
        "region": "Provence-Alpes-Côte d'Azur",
        "domain": "marseille.fr",
        "mx": ["de-smtp-inbound-1.mimecast.com", "de-smtp-inbound-2.mimecast.com"],
        "provider": "local",
        "gateway": "mimecast",
    },
    # Lyon (69123) : la DILA ne fournit pas de domaine pour la mairie centrale
    # mairie-lyon.fr → gateway Hornetsecurity
    # mesmessages.mairie-lyon.fr/owa → OWA (Outlook Web App) = Microsoft Exchange/365
    # Le include:mx.ovh.com dans SPF est un relais d'envoi résiduel, pas l'hébergeur principal
    "69123": {
        "name": "Mairie de Lyon",
        "departement": "Rhône",
        "region": "Auvergne-Rhône-Alpes",
        "domain": "mairie-lyon.fr",
        "mx": ["vade-mx-eu-fallback01.hornetsecurity.com"],
        "provider": "microsoft",
        "gateway": "hornetsecurity",
    },
    # Paris (75056) : la DILA ne fournit pas de domaine pour la mairie centrale
    # paris.fr → MX iphmx.com (Cisco Secure Email gateway)
    # SPF pointe vers Microsoft 365 (spf.protection.outlook.com)
    "75056": {
        "name": "Mairie de Paris",
        "departement": "Paris",
        "region": "Île-de-France",
        "domain": "paris.fr",
        "mx": ["mx1.hc2479-79.eu.iphmx.com", "mx2.hc2479-79.eu.iphmx.com"],
        "provider": "microsoft",
        "gateway": "cisco",
    },
    # Valence-en-Poitou (86082) : commune nouvelle (2019, fusion de 5 communes)
    # absente de la DILA. valenceenpoitou.fr → gateway VadeSecure, SPF pointe vers
    # des hôtes Zimbra (alpi40.fr) -> hébergeur réel = Zimbra
    "86082": {
        "name": "Mairie - Valence-en-Poitou",
        "departement": "Vienne",
        "region": "Nouvelle-Aquitaine",
        "domain": "valenceenpoitou.fr",
        "mx": [
            "mx01.cloud.vadesecure.com", "mx02.cloud.vadesecure.com",
            "mx03.cloud.vadesecure.com", "mx04.cloud.vadesecure.com",
        ],
        "spf": "v=spf1 include:spf.cloud.vadesecure.com a:zimbra-prod.alpi40.fr "
               "a:zimbra-proxy.alpi40.fr a:zimbra2.alpi40.fr ~all",
        "provider": "zimbra",
        "gateway": "vadesecure",
    },
    # Chantepérier (38073) : commune nouvelle (2019, fusion Chantelouve + Le Périer)
    # absente de la DILA. Pas de domaine dédié - contact via mairie.chanteperier38@orange.fr
    "38073": {
        "name": "Mairie - Chantepérier",
        "departement": "Isère",
        "region": "Auvergne-Rhône-Alpes",
        "domain": "orange.fr",
        "mx": [],
        "provider": "orange",
        "contact_email": "mairie.chanteperier38@orange.fr",
    },
}


async def run(data_path: Path) -> None:
    with open(data_path, encoding="utf-8") as f:
        data = json.load(f)

    communes = data["communes"]

    # Step 1: Apply manual overrides
    print("Applying manual overrides...")
    dns_relookup = []  # (insee, domain) pairs needing MX/SPF re-lookup
    for insee, override in MANUAL_OVERRIDES.items():
        if insee not in communes and "name" in override:
            communes[insee] = {
                "insee": insee,
                "name": override["name"],
                "departement": override.get("departement", ""),
                "region": override.get("region", ""),
                "domain": "",
                "mx": [],
                "spf": "",
                "provider": "unknown",
            }
            print(f"  {insee:>6} {override['name']:<30} (added missing commune)")
        if insee not in communes:
            continue
        if "name" in override:
            communes[insee]["name"] = override["name"]
        if "departement" in override:
            communes[insee]["departement"] = override["departement"]
        if "region" in override:
            communes[insee]["region"] = override["region"]
        if "domain" in override:
            communes[insee]["domain"] = override["domain"]
        if "provider" in override:
            communes[insee]["provider"] = override["provider"]
        if "gateway" in override:
            communes[insee]["gateway"] = override["gateway"]
        if "mx" in override:
            communes[insee]["mx"] = override["mx"]
        if "spf" in override:
            communes[insee]["spf"] = override["spf"]
        if "contact_email" in override:
            communes[insee]["contact_email"] = override["contact_email"]
        if override.get("provider") == "merged":
            communes[insee]["mx"] = []
            communes[insee]["spf"] = ""
        # Domain-only override: need to re-lookup MX/SPF from DNS
        if (
            "domain" in override
            and override["domain"]
            and "mx" not in override
            and "provider" not in override
        ):
            dns_relookup.append((insee, override["domain"]))
        else:
            print(
                f"  {insee:>6} {communes[insee]['name']:<30} -> {override.get('provider', '?')}"
            )

    if dns_relookup:

        async def _relookup(insee, domain):
            mx = await lookup_mx(domain)
            spf = await lookup_spf(domain)
            spf_resolved = await resolve_spf_includes(spf) if spf else ""
            mx_cnames = await resolve_mx_cnames(mx) if mx else {}
            mx_asns = await resolve_mx_asns(mx) if mx else set()
            autodiscover = await lookup_autodiscover(domain)
            provider = classify(
                mx,
                spf,
                mx_cnames=mx_cnames,
                mx_asns=mx_asns or None,
                resolved_spf=spf_resolved or None,
                autodiscover=autodiscover or None,
            )
            gateway = detect_gateway(mx) if mx else None
            return (
                insee,
                mx,
                spf,
                spf_resolved,
                mx_cnames,
                mx_asns,
                provider,
                gateway,
                autodiscover,
            )

        results = await asyncio.gather(*[_relookup(i, d) for i, d in dns_relookup])
        for (
            insee,
            mx,
            spf,
            spf_resolved,
            mx_cnames,
            mx_asns,
            provider,
            gateway,
            autodiscover,
        ) in results:
            communes[insee]["mx"] = mx
            communes[insee]["spf"] = spf
            communes[insee]["provider"] = provider
            if spf_resolved and spf_resolved != spf:
                communes[insee]["spf_resolved"] = spf_resolved
            if gateway:
                communes[insee]["gateway"] = gateway
            if mx_cnames:
                communes[insee]["mx_cnames"] = mx_cnames
            if mx_asns:
                communes[insee]["mx_asns"] = sorted(mx_asns)
            if autodiscover:
                communes[insee]["autodiscover"] = autodiscover
            print(
                f"  {insee:>6} {communes[insee]['name']:<30} -> {provider} (DNS re-lookup)"
            )

    # Step 1.5 : Pour les communes unknown/independent sans MX,
    # tenter autodiscover et SPF comme signaux de classification
    print("\nTentative de classification via autodiscover et SPF...")
    reclassified_via_signals = 0
    for m in communes.values():
        if m["provider"] not in ("unknown", "independent"):
            continue
        if m.get("mx"):  # a déjà un MX → déjà traité
            continue
        domain = m.get("domain", "")
        if not domain:
            continue

        provider_found = None
        confidence_note = ""

        # Signal 1 : autodiscover existant
        autodiscover = m.get("autodiscover", {})
        if autodiscover:
            ad_blob = " ".join(autodiscover.values()).lower()
            if any(k in ad_blob for k in ["outlook.com", "office365", "microsoft", "protection.outlook"]):
                provider_found = "microsoft"
                confidence_note = "autodiscover→outlook"
            elif any(k in ad_blob for k in ["google", "gmail"]):
                provider_found = "google"
                confidence_note = "autodiscover→google"

        # Signal 2 : SPF (seulement si pas déjà trouvé via autodiscover)
        if not provider_found:
            spf_blob = (m.get("spf", "") + " " + m.get("spf_resolved", "")).lower()
            if spf_blob.strip():
                if any(k in spf_blob for k in ["spf.protection.outlook.com", "protection.outlook", "office365", "onmicrosoft"]):
                    provider_found = "microsoft"
                    confidence_note = "spf→outlook"
                elif any(k in spf_blob for k in ["_spf.google.com", "aspmx.l.google.com", "gmail.com"]):
                    provider_found = "google"
                    confidence_note = "spf→google"
                elif any(k in spf_blob for k in ["ovh.net", "ovhcloud.com", "mx.ovh.com"]):
                    provider_found = "ovh"
                    confidence_note = "spf→ovh"
                elif any(k in spf_blob for k in ["gandi.net"]):
                    provider_found = "gandi"
                    confidence_note = "spf→gandi"
                elif any(k in spf_blob for k in ["infomaniak.com", "infomaniak.ch"]):
                    provider_found = "infomaniak"
                    confidence_note = "spf→infomaniak"

        if provider_found:
            m["provider"] = provider_found
            m["_confidence_note"] = confidence_note
            reclassified_via_signals += 1

    print(f"  {reclassified_via_signals} communes reclassifiées via autodiscover/SPF")

    # Step 2: Retry DNS for unknowns that have a domain (asynchrone + verbose)
    dns_retry_candidates = [
        m for m in communes.values() if m["provider"] == "unknown" and m.get("domain")
    ]
    if dns_retry_candidates:
        print(f"\nRetrying DNS for {len(dns_retry_candidates)} unknown domains...")

        async def _dns_retry(m: dict[str, Any], sem: asyncio.Semaphore) -> dict[str, Any]:
            async with sem:
                domain = m["domain"]
                mx = await lookup_mx(domain)

                if not mx:
                    return m
                spf = await lookup_spf(domain)
                spf_resolved = await resolve_spf_includes(spf) if spf else ""
                mx_cnames = await resolve_mx_cnames(mx)
                mx_asns = await resolve_mx_asns(mx)
                autodiscover = await lookup_autodiscover(domain)
                provider = classify(
                    mx, spf,
                    mx_cnames=mx_cnames,
                    mx_asns=mx_asns or None,
                    resolved_spf=spf_resolved or None,
                    autodiscover=autodiscover or None,
                )
                gateway = detect_gateway(mx)
                m["mx"] = mx
                m["spf"] = spf
                m["provider"] = provider
                if spf_resolved and spf_resolved != spf:
                    m["spf_resolved"] = spf_resolved
                if gateway:
                    m["gateway"] = gateway
                if mx_cnames:
                    m["mx_cnames"] = mx_cnames
                if mx_asns:
                    m["mx_asns"] = sorted(mx_asns)
                if autodiscover:
                    m["autodiscover"] = autodiscover
                return m

        retry_sem = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)
        retry_tasks = [_dns_retry(m, retry_sem) for m in dns_retry_candidates]
        recovered = 0
        done_retry = 0
        total_retry = len(retry_tasks)
        no_mx_domains: list[str] = []

        for coro in asyncio.as_completed(retry_tasks):
            m = await coro
            done_retry += 1
            if m["provider"] != "unknown":
                recovered += 1
                print(
                    f"  RECOVERED [{done_retry:4d}/{total_retry}] "
                    f"{m['insee']:>6} {m['name']:<30} "
                    f"domain={m['domain']:<35} -> {m['provider']}"
                )
            else:
                no_mx_domains.append(m["domain"])
                if done_retry % 100 == 0 or done_retry == total_retry:
                    print(
                        f"  Progress  [{done_retry:4d}/{total_retry}] "
                        f"recovered={recovered} still_unknown={done_retry - recovered}"
                    )

        print(f"  DNS retry complete : {recovered}/{total_retry} resolus")
        if no_mx_domains:
            # Afficher un echantillon des domaines sans MX
            sample = no_mx_domains[:20]
            print(f"  Domaines sans MX ({len(no_mx_domains)} total, echantillon) :")
            for d in sample:
                print(f"    {d}")
            if len(no_mx_domains) > 20:
                print(f"    ... et {len(no_mx_domains) - 20} autres")

    # Step 2.5: SMTP banner check for independent/unknown with MX records
    smtp_candidates = [
        m
        for m in communes.values()
        if m["provider"] in ("independent", "unknown") and m.get("mx")
    ]
    if smtp_candidates:
        mx_host_to_insee: dict[str, list[str]] = {}
        for m in smtp_candidates:
            primary_mx = m["mx"][0]
            mx_host_to_insee.setdefault(primary_mx, []).append(m["insee"])

        print(
            f"\nSMTP banner check: {len(smtp_candidates)} entries, "
            f"{len(mx_host_to_insee)} unique MX hosts..."
        )
        smtp_semaphore = asyncio.Semaphore(CONCURRENCY_SMTP)

        async def _fetch_banner(mx_host: str) -> tuple[str, dict[str, str]]:
            async with smtp_semaphore:
                res = await fetch_smtp_banner(mx_host)
                return mx_host, res

        banner_results = await asyncio.gather(
            *[_fetch_banner(host) for host in mx_host_to_insee]
        )

        smtp_reclassified = 0
        for mx_host, result in banner_results:
            banner = result.get("banner", "")
            ehlo = result.get("ehlo", "")
            if not banner:
                continue
            provider = classify_from_smtp_banner(banner, ehlo)
            for insee in mx_host_to_insee[mx_host]:
                communes[insee]["smtp_banner"] = banner
                if provider and communes[insee]["provider"] in ("independent", "unknown"):
                    old = communes[insee]["provider"]
                    communes[insee]["provider"] = provider
                    smtp_reclassified += 1
                    print(
                        f"  SMTP     {insee:>6} {communes[insee]['name']:<30} "
                        f"{old} -> {provider} ({mx_host})"
                    )

        print(f"  SMTP reclassified: {smtp_reclassified}")

    # Step 3: Scrape remaining unknowns
    unknowns = [m for m in communes.values() if m["provider"] == "unknown"]
    print(f"\n{len(unknowns)} unknown communes to investigate\n")

    if unknowns:
        semaphore = asyncio.Semaphore(CONCURRENCY_POSTPROCESS)
        async with httpx.AsyncClient(
            headers={
                "User-Agent": "mxmap.fr/1.0 (https://github.com/davidhuser/mxmap)"
            },
            follow_redirects=True,
        ) as client:
            tasks = [process_unknown(client, semaphore, m) for m in unknowns]
            results = await asyncio.gather(*tasks)

        resolved = 0
        for m in results:
            communes[m["insee"]] = m
            if m["provider"] != "unknown":
                resolved += 1
        print(f"\nResolved {resolved}/{len(unknowns)} via scraping")

    # Etape : mairies déléguées/associées - doublons administratifs d'une commune
    # nouvelle déjà représentée sous un autre code INSEE. La DILA référence
    # chaque ancienne mairie sous son propre code INSEE (ex: 01039 Béon), alors
    # que geo.api.gouv.fr (et donc communes.pmtiles) ne fournit plus de géométrie
    # que pour la commune nouvelle issue de la fusion (ex: 01138 Culoz-Béon).
    # Sans ce filtre, ces doublons restent dans data.json sans jamais s'afficher
    # sur la carte (aucune géométrie à ce code INSEE) et faussent les compteurs
    # (une même commune comptée deux fois). On les retire quand la commune de
    # rattachement (COG "COMPARENT") a bien sa propre entrée dans data.json.
    print("\nRésolution des mairies déléguées/associées (doublons commune nouvelle)...")
    try:
        async with httpx.AsyncClient(follow_redirects=True, verify=False) as client:
            cog_csv = await _fetch_cog_csv(client)
        deleguee_parents = _parse_deleguee_parents(cog_csv)
    except Exception as e:
        print(f"  ATTENTION : téléchargement COG échoué ({e}), étape ignorée")
        deleguee_parents = {}

    dropped = 0
    for insee in list(communes.keys()):
        parent_insee = deleguee_parents.get(insee)
        if parent_insee and parent_insee != insee and parent_insee in communes:
            print(f"    {insee} {communes[insee]['name'][:40]} -> doublon de {parent_insee} ({communes[parent_insee]['name']}), retiré")
            del communes[insee]
            dropped += 1
    print(f"  {dropped} mairies déléguées/associées retirées")

    # Etape : un gateway n'est jamais un provider final (cf. règle VadeSecure).
    # classify.py retourne désormais "unknown" quand aucun hébergeur n'est
    # identifiable derrière un gateway, mais les communes déjà classées lors
    # d'un run preprocess antérieur (avant ce fix) peuvent encore porter le nom
    # du gateway comme provider - valeur absente de COLORS/LEGEND_GROUPS côté
    # frontend, qui rendait la commune invisible (transparente) sur la carte
    # au lieu de grise "Inconnu". Le champ `gateway` reste renseigné séparément.
    gateway_as_provider = 0
    for m in communes.values():
        if m["provider"] in GATEWAY_KEYWORDS:
            m["provider"] = "unknown"
            gateway_as_provider += 1
    if gateway_as_provider:
        print(f"\n  {gateway_as_provider} communes avec gateway comme provider -> reclassifiees unknown")

    # Etape : domaines mutualisés mal classés "local" par un run preprocess
    # antérieur (avant fix). Ex: laposte.net (La Poste Pro, email mutualisé pour
    # collectivités) - la racine du MX matche la racine du domaine testé, ce qui
    # déclenchait la règle d'auto-hébergement "local", alors que des centaines de
    # communes différentes partagent ce même domaine (cf. SHARED_EMAIL_DOMAINS,
    # "jamais de l'auto-hébergement communal").
    shared_domain_as_local = 0
    for m in communes.values():
        if m["provider"] == "local" and m.get("domain", "") in SHARED_EMAIL_DOMAINS:
            m["provider"] = "independent"
            shared_domain_as_local += 1
    if shared_domain_as_local:
        print(f"  {shared_domain_as_local} communes sur domaine mutualisé mal classées local -> reclassifiees independent")

    # Etape finale : masquer la partie locale des emails avant publication
    # mairie-xxx@orange.fr -> [omis]@orange.fr
    email_masked = 0
    for m in communes.values():
        raw = m.get("contact_email", "")
        if raw and "@" in raw:
            domain_part = raw.split("@", 1)[1]
            m["contact_email"] = f"[omis]@{domain_part}"
            email_masked += 1
    print(f"  {email_masked} adresses email masquees")

    # Souveraineté : cloud non-EU (microsoft/google/aws/yahoo) ou gateway non-EU
    # (barracuda/proofpoint/cisco/fortinet/sophos/trendmicro/mimecast) vs EU
    for m in communes.values():
        m["sovereignty"] = classify_sovereignty(m["provider"], m.get("gateway"))

    # Recompute counts
    counts: dict[str, int] = {}
    sovereignty_counts: dict[str, int] = {}
    for m in communes.values():
        counts[m["provider"]] = counts.get(m["provider"], 0) + 1
        sovereignty_counts[m["sovereignty"]] = sovereignty_counts.get(m["sovereignty"], 0) + 1
    data["counts"] = dict(sorted(counts.items()))
    data["sovereignty_counts"] = dict(sorted(sovereignty_counts.items()))
    data["total"] = len(communes)
    data["communes"] = dict(sorted(communes.items(), key=lambda kv: kv[0]))

    remaining = counts.get("unknown", 0)
    print(f"\nFinal counts: {json.dumps(counts)}")

    if remaining > 0:
        print(f"\nStill unknown ({remaining}, for manual review):")
        for m in sorted(communes.values(), key=lambda x: x["insee"]):
            if m["provider"] == "unknown":
                print(
                    f"  {m['insee']:>6}  {m['name']:<30} "
                    f"{m.get('departement', ''):.<20} domain={m['domain']}"
                )

    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2, separators=(",", ":"))

    print(f"\nUpdated {data_path}")

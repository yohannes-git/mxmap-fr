import asyncio
import io
import json
import re
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from mail_sovereignty.classify import classify, detect_gateway
from mail_sovereignty.constants import CONCURRENCY, SPARQL_URL, SPARQL_QUERY
from mail_sovereignty.dns import (
    lookup_autodiscover,
    lookup_mx,
    lookup_spf,
    resolve_mx_asns,
    resolve_mx_cnames,
    resolve_spf_includes,
)

# Archive quotidienne DILA contenant toutes les donnees locales service-public.fr
DILA_TAR_URL = (
    "https://lecomarquage.service-public.gouv.fr/donnees_locales_v4/all_latest.tar.bz2"
)
# Nom du fichier JSON des services locaux dans l'archive (le prefixe date change chaque jour)
DILA_LOCAL_JSON_SUFFIX = "data.gouv_local.json"
# Cache local : evite de retelecharger 350 Mo si le fichier a moins de 23h
DILA_CACHE_PATH = Path(".dila_cache.tar.bz2")
DILA_CACHE_MAX_AGE_HOURS = 23

# TopoJSON des communes françaises
TOPOJSON_PATH = Path("france-communes.json")
TOPOJSON_MAX_AGE_DAYS = 30  # les contours ne changent pas souvent
GEOJSON_TMP_PATH = Path("communes-tmp.geojson")

# Departements pour le téléchargement IGN
ALL_DEPT_CODES = [
    "01","02","03","04","05","06","07","08","09","10",
    "11","12","13","14","15","16","17","18","19","2A",
    "2B","21","22","23","24","25","26","27","28","29",
    "30","31","32","33","34","35","36","37","38","39","40",
    "41","42","43","44","45","46","47","48","49","50",
    "51","52","53","54","55","56","57","58","59","60",
    "61","62","63","64","65","66","67","68","69","70",
    "71","72","73","74","75","76","77","78","79","80",
    "81","82","83","84","85","86","87","88","89","90",
    "91","92","93","94","95",
    "971","972","973","974","976",
]

DEPT_TO_REGION = {
    "01":"Auvergne-Rhone-Alpes","02":"Hauts-de-France","03":"Auvergne-Rhone-Alpes",
    "04":"Provence-Alpes-Cote d'Azur","05":"Provence-Alpes-Cote d'Azur",
    "06":"Provence-Alpes-Cote d'Azur","07":"Auvergne-Rhone-Alpes","08":"Grand Est",
    "09":"Occitanie","10":"Grand Est","11":"Occitanie","12":"Occitanie",
    "13":"Provence-Alpes-Cote d'Azur","14":"Normandie","15":"Auvergne-Rhone-Alpes",
    "16":"Nouvelle-Aquitaine","17":"Nouvelle-Aquitaine","18":"Centre-Val de Loire",
    "19":"Nouvelle-Aquitaine","21":"Bourgogne-Franche-Comte","22":"Bretagne",
    "23":"Nouvelle-Aquitaine","24":"Nouvelle-Aquitaine","25":"Bourgogne-Franche-Comte",
    "26":"Auvergne-Rhone-Alpes","27":"Normandie","28":"Centre-Val de Loire",
    "29":"Bretagne","2A":"Corse","2B":"Corse","30":"Occitanie",
    "31":"Occitanie","32":"Occitanie","33":"Nouvelle-Aquitaine","34":"Occitanie",
    "35":"Bretagne","36":"Centre-Val de Loire","37":"Centre-Val de Loire",
    "38":"Auvergne-Rhone-Alpes","39":"Bourgogne-Franche-Comte","40":"Nouvelle-Aquitaine",
    "41":"Centre-Val de Loire","42":"Auvergne-Rhone-Alpes","43":"Auvergne-Rhone-Alpes",
    "44":"Pays de la Loire","45":"Centre-Val de Loire","46":"Occitanie",
    "47":"Nouvelle-Aquitaine","48":"Occitanie","49":"Pays de la Loire","50":"Normandie",
    "51":"Grand Est","52":"Grand Est","53":"Pays de la Loire","54":"Grand Est",
    "55":"Grand Est","56":"Bretagne","57":"Grand Est","58":"Bourgogne-Franche-Comte",
    "59":"Hauts-de-France","60":"Hauts-de-France","61":"Normandie","62":"Hauts-de-France",
    "63":"Auvergne-Rhone-Alpes","64":"Nouvelle-Aquitaine","65":"Occitanie",
    "66":"Occitanie","67":"Grand Est","68":"Grand Est","69":"Auvergne-Rhone-Alpes",
    "70":"Bourgogne-Franche-Comte","71":"Bourgogne-Franche-Comte","72":"Pays de la Loire",
    "73":"Auvergne-Rhone-Alpes","74":"Auvergne-Rhone-Alpes","75":"Ile-de-France",
    "76":"Normandie","77":"Ile-de-France","78":"Ile-de-France","79":"Nouvelle-Aquitaine",
    "80":"Hauts-de-France","81":"Occitanie","82":"Occitanie",
    "83":"Provence-Alpes-Cote d'Azur","84":"Provence-Alpes-Cote d'Azur",
    "85":"Pays de la Loire","86":"Nouvelle-Aquitaine","87":"Nouvelle-Aquitaine",
    "88":"Grand Est","89":"Bourgogne-Franche-Comte","90":"Bourgogne-Franche-Comte",
    "91":"Ile-de-France","92":"Ile-de-France","93":"Ile-de-France","94":"Ile-de-France",
    "95":"Ile-de-France","971":"Guadeloupe","972":"Martinique","973":"Guyane",
    "974":"La Reunion","976":"Mayotte",
}

DEPT_NAMES = {
    "01":"Ain","02":"Aisne","03":"Allier","04":"Alpes-de-Haute-Provence",
    "05":"Hautes-Alpes","06":"Alpes-Maritimes","07":"Ardeche","08":"Ardennes",
    "09":"Ariege","10":"Aube","11":"Aude","12":"Aveyron","13":"Bouches-du-Rhone",
    "14":"Calvados","15":"Cantal","16":"Charente","17":"Charente-Maritime",
    "18":"Cher","19":"Correze","2A":"Corse-du-Sud","2B":"Haute-Corse",
    "21":"Cote-d'Or","22":"Cotes-d'Armor","23":"Creuse","24":"Dordogne",
    "25":"Doubs","26":"Drome","27":"Eure","28":"Eure-et-Loir","29":"Finistere",
    "30":"Gard","31":"Haute-Garonne","32":"Gers","33":"Gironde","34":"Herault",
    "35":"Ille-et-Vilaine","36":"Indre","37":"Indre-et-Loire","38":"Isere",
    "39":"Jura","40":"Landes","41":"Loir-et-Cher","42":"Loire","43":"Haute-Loire",
    "44":"Loire-Atlantique","45":"Loiret","46":"Lot","47":"Lot-et-Garonne",
    "48":"Lozere","49":"Maine-et-Loire","50":"Manche","51":"Marne",
    "52":"Haute-Marne","53":"Mayenne","54":"Meurthe-et-Moselle","55":"Meuse",
    "56":"Morbihan","57":"Moselle","58":"Nievre","59":"Nord","60":"Oise",
    "61":"Orne","62":"Pas-de-Calais","63":"Puy-de-Dome","64":"Pyrenees-Atlantiques",
    "65":"Hautes-Pyrenees","66":"Pyrenees-Orientales","67":"Bas-Rhin","68":"Haut-Rhin",
    "69":"Rhone","70":"Haute-Saone","71":"Saone-et-Loire","72":"Sarthe","73":"Savoie",
    "74":"Haute-Savoie","75":"Paris","76":"Seine-Maritime","77":"Seine-et-Marne",
    "78":"Yvelines","79":"Deux-Sevres","80":"Somme","81":"Tarn","82":"Tarn-et-Garonne",
    "83":"Var","84":"Vaucluse","85":"Vendee","86":"Vienne","87":"Haute-Vienne",
    "88":"Vosges","89":"Yonne","90":"Territoire de Belfort","91":"Essonne",
    "92":"Hauts-de-Seine","93":"Seine-Saint-Denis","94":"Val-de-Marne","95":"Val-d'Oise",
    "971":"Guadeloupe","972":"Martinique","973":"Guyane","974":"La Reunion","976":"Mayotte",
}


def dept_from_insee(insee: str) -> str:
    if insee.startswith("97"):
        return insee[:3]
    if len(insee) >= 2 and insee[:2].upper() in ("2A", "2B"):
        return insee[:2].upper()
    return insee[:2]


def url_to_domain(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.hostname or ""
    if host.startswith("www."):
        host = host[4:]
    return host if host else None


def guess_domains(name: str) -> list[str]:
    raw = name.lower().strip()
    raw = re.sub(r"\s*\(.*?\)\s*", "", raw)
    raw = re.sub(r"^mairie\s*[-]\s*", "", raw)
    fr = raw
    for a, b in [
        ("\u00e9","e"),("\u00e8","e"),("\u00ea","e"),("\u00eb","e"),
        ("\u00e0","a"),("\u00e2","a"),("\u00f4","o"),("\u00ee","i"),
        ("\u00f9","u"),("\u00fb","u"),("\u00e7","c"),("\u00ef","i"),
        ("\u00f3","o"),("\u00fa","u"),
    ]:
        fr = fr.replace(a, b)

    def slugify(s):
        s = re.sub(r"['\u2019`]", "", s)
        s = re.sub(r"[^a-z0-9]+", "-", s)
        return s.strip("-")

    slugs = {slugify(fr), slugify(raw)} - {""}
    candidates = set()
    for slug in slugs:
        candidates.add(f"{slug}.fr")
        candidates.add(f"mairie-{slug}.fr")
        candidates.add(f"ville-{slug}.fr")
        candidates.add(f"commune-{slug}.fr")
    return sorted(candidates)


def parse_service(svc: dict) -> tuple[str, dict[str, str]] | None:
    """
    Convertit un enregistrement service DILA en entree commune.
    Retourne (insee, dict) ou None si ce n'est pas une mairie.
    """
    pivots = svc.get("pivot", [])
    insee = None
    for p in pivots:
        if p.get("type_service_local") == "mairie":
            codes = p.get("code_insee_commune", [])
            if codes:
                insee = codes[0] if isinstance(codes, list) else codes
            break
    if not insee:
        return None

    name = (svc.get("nom") or f"INSEE-{insee}").strip()

    # site_internet est une liste de dicts {"libelle": "", "valeur": "https://..."}
    sites = svc.get("site_internet") or []
    website = sites[0].get("valeur", "") if sites else ""

    # adresse_courriel est une liste de chaines
    dept_code = dept_from_insee(insee)
    return insee, {
        "insee": insee,
        "name": name,
        "website": website,
        "departement": DEPT_NAMES.get(dept_code, ""),
        "region": DEPT_TO_REGION.get(dept_code, ""),
            }


def _check_mapshaper() -> bool:
    """Verifie que mapshaper est installe."""
    try:
        subprocess.run(["mapshaper", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


async def fetch_topojson(topojson_path: Path = TOPOJSON_PATH) -> None:
    """
    Genere le TopoJSON des communes françaises si absent ou trop ancien.

    Etapes :
      1. Telecharge les contours commune par commune depuis l'API geo.api.gouv.fr
      2. Fusionne en un seul GeoJSON
      3. Convertit en TopoJSON simplifié avec mapshaper
    """
    if topojson_path.exists():
        age_days = (time.time() - topojson_path.stat().st_mtime) / 86400
        if age_days < TOPOJSON_MAX_AGE_DAYS:
            print(
                f"TopoJSON valide ({age_days:.0f}j < {TOPOJSON_MAX_AGE_DAYS}j) : "
                f"{topojson_path} ({topojson_path.stat().st_size / 1024:.0f} Ko)"
            )
            return
        print(f"TopoJSON expire ({age_days:.0f}j), regeneration...")
    else:
        print(f"TopoJSON absent, generation de {topojson_path}...")

    if not _check_mapshaper():
        print("  ATTENTION : mapshaper non trouve. Installez-le avec : npm install -g mapshaper")
        print("  Le TopoJSON ne sera pas genere — la carte ne s'affichera pas correctement.")
        return

    # Etape 1 : téléchargement GeoJSON par département (API IGN)
    print(f"  Telechargement des contours communes depuis geo.api.gouv.fr...")
    all_features = []
    total_depts = len(ALL_DEPT_CODES)
    for i, dept in enumerate(ALL_DEPT_CODES):
        url = (
            f"https://geo.api.gouv.fr/communes"
            f"?codeDepartement={dept}&fields=code,nom&format=geojson&geometry=contour"
        )
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                g = json.loads(r.read())
                all_features.extend(g["features"])
        except Exception as e:
            print(f"  ERREUR dept {dept}: {e}")
        print(
            f"  [{i+1:3d}/{total_depts}] dept {dept:>3} "
            f"| {len(all_features)} communes",
            end="\r",
        )
        time.sleep(0.05)

    print(f"\n  {len(all_features)} communes téléchargées")

    # Etape 2 : écriture du GeoJSON temporaire
    geojson = {"type": "FeatureCollection", "features": all_features}
    with open(GEOJSON_TMP_PATH, "w", encoding="utf-8") as f:
        json.dump(geojson, f)

    # Etape 3 : conversion en TopoJSON avec mapshaper
    print(f"  Conversion en TopoJSON avec mapshaper...")
    cmd = [
        "mapshaper", str(GEOJSON_TMP_PATH),
        "-rename-layers", "communes",
        "-each", "this.id = this.properties.code",
        "-simplify", "5%", "weighted", "keep-shapes",
        "-o", "format=topojson", "quantization=1e4", str(topojson_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERREUR mapshaper : {result.stderr}")
    else:
        size_kb = topojson_path.stat().st_size / 1024
        print(f"  TopoJSON genere : {topojson_path} ({size_kb:.0f} Ko)")

    # Nettoyage du fichier temporaire
    GEOJSON_TMP_PATH.unlink(missing_ok=True)


async def fetch_dila() -> dict[str, dict[str, str]]:
    """
    Telecharge l'archive DILA all_latest.tar.bz2 (~350 Mo) et extrait
    toutes les mairies depuis le fichier JSON local qu'elle contient.

    Structure de l'archive :
      ./YYYYMMDD_HHMMSS-data.gouv_local.json   <- 86 000 services locaux
      ./YYYYMMDD_HHMMSS-data.gouv_commune.zip  <- index commune -> UUIDs services

    Le fichier est mis en cache localement pendant 23h pour eviter un
    retelechargement inutile lors des relances dans la meme journee.
    """
    tar_bytes: bytes | None = None

    # Verifier le cache
    if DILA_CACHE_PATH.exists():
        age_hours = (time.time() - DILA_CACHE_PATH.stat().st_mtime) / 3600
        if age_hours < DILA_CACHE_MAX_AGE_HOURS:
            print(
                f"Cache DILA valide ({age_hours:.1f}h < {DILA_CACHE_MAX_AGE_HOURS}h), "
                f"reutilisation de {DILA_CACHE_PATH} "
                f"({DILA_CACHE_PATH.stat().st_size / 1024 / 1024:.0f} Mo)..."
            )
            tar_bytes = DILA_CACHE_PATH.read_bytes()
        else:
            print(f"Cache DILA expire ({age_hours:.1f}h), nouveau telechargement...")

    if tar_bytes is None:
        print("Telechargement de l'archive DILA service-public.fr...")
        print(f"  URL : {DILA_TAR_URL}")
        print("  Taille : ~350 Mo, patience...")
        async with httpx.AsyncClient(timeout=300) as client:
            r = await client.get(DILA_TAR_URL)
            r.raise_for_status()
            tar_bytes = r.content
        DILA_CACHE_PATH.write_bytes(tar_bytes)
        print(
            f"  Telechargement termine ({len(tar_bytes) / 1024 / 1024:.0f} Mo), "
            f"cache ecrit dans {DILA_CACHE_PATH}"
        )

    print("  Extraction et parsing...")

    # Ouvrir le tar.bz2 en memoire
    tar_io = io.BytesIO(tar_bytes)
    communes: dict[str, dict[str, str]] = {}

    with tarfile.open(fileobj=tar_io, mode="r:bz2") as tar:
        for member in tar.getmembers():
            if not member.name.endswith(DILA_LOCAL_JSON_SUFFIX):
                continue
            f = tar.extractfile(member)
            if f is None:
                continue
            print(f"  Fichier trouve : {member.name}")
            data = json.load(f)
            services = data.get("service", [])
            print(f"  {len(services)} services a parser...")

            for svc in services:
                result = parse_service(svc)
                if result is None:
                    continue
                insee, commune = result
                if insee not in communes:
                    communes[insee] = commune
                elif not communes[insee]["website"] and commune["website"]:
                    communes[insee]["website"] = commune["website"]
            break  # Un seul fichier JSON local dans l'archive

    print(
        f"  {len(communes)} mairies extraites, "
        f"{sum(1 for c in communes.values() if c['website'])} avec site web"
    )
    return communes


async def fetch_wikidata() -> dict[str, dict[str, str]]:
    """Fallback Wikidata pour les communes absentes de l'archive DILA."""
    if not SPARQL_QUERY:
        return {}
    print("Requete Wikidata (fallback)...")
    headers = {
        "Accept": "application/sparql-results+json",
        "User-Agent": "MXmap/1.0 (https://github.com/davidhuser/mxmap)",
    }
    try:
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.post(SPARQL_URL, data={"query": SPARQL_QUERY}, headers=headers)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        print(f"  Wikidata indisponible ({e}), fallback ignore.")
        return {}
    communes: dict[str, dict[str, str]] = {}
    for row in data["results"]["bindings"]:
        insee = row["insee"]["value"]
        name = row.get("communeLabel", {}).get("value", f"INSEE-{insee}")
        website = row.get("website", {}).get("value", "")
        departement = row.get("departementLabel", {}).get("value", "")
        region = row.get("regionLabel", {}).get("value", "")
        if insee not in communes:
            communes[insee] = {
                "insee": insee, "name": name, "website": website,
                "departement": departement, "region": region,             }
        elif not communes[insee]["website"] and website:
            communes[insee]["website"] = website
    print(f"  {len(communes)} communes depuis Wikidata")
    return communes


async def scan_commune(m: dict[str, str], semaphore: asyncio.Semaphore) -> dict[str, Any]:
    async with semaphore:
        domain = url_to_domain(m.get("website", ""))
        mx, spf = [], ""

        # 1. Essayer le domaine du site web
        if domain:
            mx = await lookup_mx(domain)
            if mx:
                spf = await lookup_spf(domain)

        # 2. Essayer des variantes de domaine devinées depuis le nom de la commune
        if not mx:
            for guess in guess_domains(m["name"]):
                if guess == domain:
                    continue
                mx = await lookup_mx(guess)
                if mx:
                    domain = guess
                    spf = await lookup_spf(guess)
                    break
        spf_resolved = await resolve_spf_includes(spf) if spf else ""
        mx_cnames = await resolve_mx_cnames(mx) if mx else {}
        mx_asns = await resolve_mx_asns(mx) if mx else set()
        autodiscover = await lookup_autodiscover(domain) if domain else {}
        provider = classify(
            mx, spf, mx_cnames=mx_cnames, mx_asns=mx_asns or None,
            resolved_spf=spf_resolved or None, autodiscover=autodiscover or None,
        )
        gateway = detect_gateway(mx) if mx else None
        entry: dict[str, Any] = {
            "insee": m["insee"],
            "name": m["name"],
            "departement": m.get("departement", ""),
            "region": m.get("region", ""),
            "domain": domain or "",
            "mx": mx,
            "spf": spf,
            "provider": provider,
        }
        if spf_resolved and spf_resolved != spf:
            entry["spf_resolved"] = spf_resolved
        if gateway:
            entry["gateway"] = gateway
        if mx_cnames:
            entry["mx_cnames"] = mx_cnames
        if mx_asns:
            entry["mx_asns"] = sorted(mx_asns)
        if autodiscover:
            entry["autodiscover"] = autodiscover
        return entry


async def run(output_path: Path) -> None:
    # Générer le TopoJSON si nécessaire (contours des communes pour la carte)
    await fetch_topojson()

    communes = await fetch_dila()

    wikidata = await fetch_wikidata()
    added_from_wikidata = 0
    for insee, c in wikidata.items():
        if insee not in communes:
            communes[insee] = c
            added_from_wikidata += 1
        elif not communes[insee]["website"] and c["website"]:
            communes[insee]["website"] = c["website"]
    if added_from_wikidata:
        print(f"  {added_from_wikidata} communes ajoutees depuis Wikidata (fallback)")

    total = len(communes)
    print(f"\nScan MX/SPF de {total} communes...")
    print("(Quelques minutes avec les lookups asynchrones)\n")
    semaphore = asyncio.Semaphore(CONCURRENCY)
    tasks = [scan_commune(m, semaphore) for m in communes.values()]
    results: dict[str, Any] = {}
    done = 0
    for coro in asyncio.as_completed(tasks):
        result = await coro
        results[result["insee"]] = result
        done += 1
        if done % 50 == 0 or done == total:
            counts: dict[str, int] = {}
            for r in results.values():
                counts[r["provider"]] = counts.get(r["provider"], 0) + 1
            print(
                f"  [{done:5d}/{total}]  "
                f"MS={counts.get('microsoft', 0)}  "
                f"Google={counts.get('google', 0)}  "
                f"OVH={counts.get('ovh', 0)}  "
                f"AWS={counts.get('aws', 0)}  "
                f"Indep={counts.get('independent', 0)}  "
                f"?={counts.get('unknown', 0)}"
            )
    counts = {}
    for r in results.values():
        counts[r["provider"]] = counts.get(r["provider"], 0) + 1

    print(f"\n{'=' * 50}")
    print(f"RESULTATS : {len(results)} communes scannees")
    print(f"  Microsoft/Azure : {counts.get('microsoft', 0):>6}")
    print(f"  Google/GCP      : {counts.get('google', 0):>6}")
    print(f"  OVHcloud        : {counts.get('ovh', 0):>6}")
    print(f"  IONOS           : {counts.get('ionos', 0):>6}")
    print(f"  AWS             : {counts.get('aws', 0):>6}")
    print(f"  FAI francais    : {counts.get('french-isp', 0):>6}")
    print(f"  Independant     : {counts.get('independent', 0):>6}")
    print(f"  Inconnu/Sans MX : {counts.get('unknown', 0):>6}")
    print(f"{'=' * 50}")

    sorted_counts = dict(sorted(counts.items()))
    sorted_communes = dict(sorted(results.items(), key=lambda kv: kv[0]))
    output = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "counts": sorted_counts,
        "communes": sorted_communes,
    }
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output, f, ensure_ascii=False, indent=None, separators=(",", ":"))
    size_kb = len(json.dumps(output)) / 1024
    print(f"\nFichier ecrit : {output_path} ({size_kb:.0f} KB)")

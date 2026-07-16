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

import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS")

from mail_sovereignty.classify import classify, classify_from_mx, detect_gateway
from mail_sovereignty.constants import (
    CONCURRENCY, SPARQL_URL, SPARQL_QUERY,
    SHARED_EMAIL_DOMAINS, WEBMAIL_APPS, WEBMAIL_PROBES,
)
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

# Contours des communes françaises : tuiles vectorielles (chargement paresseux par
# viewport côté navigateur, au lieu d'un GeoJSON complet chargé d'un coup - voir
# CLAUDE.md "Rendu cartographique" pour le détail de la migration et les mesures RAM)
PMTILES_PATH = Path("communes.pmtiles")
DEPARTEMENTS_GEOJSON_PATH = Path("departements.geojson")
# Liste plate des codes INSEE couverts par communes.pmtiles - permet de vérifier
# la complétude de data.json sans dépendre d'un outil capable de lire les PMTiles
# (voir CLAUDE.md "Communes sans données")
COMMUNES_INDEX_PATH = Path("communes-index.json")
MAP_DATA_MAX_AGE_DAYS = 30  # les contours ne changent pas souvent
GEOJSON_TMP_PATH = Path("communes-tmp.geojson")
GEOJSON_SIMPLIFIED_TMP_PATH = Path("communes-simplified-tmp.geojson")

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
    """Extrait le domaine de base depuis une URL."""
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


# Codes INSEE des arrondissements de Paris, Lyon et Marseille
# Ces entités n'ont pas d'infrastructure email indépendante
# Paris : 75101-75120, Lyon : 69381-69389, Marseille : 13201-13216
_SKIP_INSEE = set()
_SKIP_INSEE.update(f"751{i:02d}" for i in range(1, 21))   # Paris
_SKIP_INSEE.update(f"6938{i}" for i in range(1, 10))       # Lyon
_SKIP_INSEE.update(f"132{i:02d}" for i in range(1, 17))    # Marseille


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
    # Ignorer les arrondissements (Paris, Lyon, Marseille)
    if insee in _SKIP_INSEE:
        return None

    name = (svc.get("nom") or f"INSEE-{insee}").strip()

    # site_internet : liste de dicts {"libelle": "", "valeur": "https://..."}
    sites = svc.get("site_internet") or []
    website = sites[0].get("valeur", "").strip() if sites else ""

    # adresse_courriel : liste de chaînes
    emails = svc.get("adresse_courriel") or []
    email = emails[0].strip() if emails else ""

    # formulaire_contact : URL de contact - on en extrait le domaine si pas de site web
    # Peut être une chaîne ou une liste selon les enregistrements DILA
    formulaire_raw = svc.get("formulaire_contact") or ""
    if isinstance(formulaire_raw, list):
        formulaire = formulaire_raw[0].strip() if formulaire_raw else ""
    else:
        formulaire = str(formulaire_raw).strip()
    if not website and formulaire:
        website = formulaire  # url_to_domain() extraira le domaine

    dept_code = dept_from_insee(insee)
    return insee, {
        "insee": insee,
        "name": name,
        "website": website,
        "departement": DEPT_NAMES.get(dept_code, ""),
        "region": DEPT_TO_REGION.get(dept_code, ""),
        "contact_email": email,
    }


def _check_mapshaper() -> bool:
    """Verifie que mapshaper est installe."""
    try:
        subprocess.run(["mapshaper", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


def _check_tippecanoe() -> bool:
    """Verifie que tippecanoe est installe (apt install tippecanoe)."""
    try:
        subprocess.run(["tippecanoe", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


# URL Admin Express COG IGN - données officielles, géométrie précise, libre d'accès
ADMINEXPRESS_URL = (
    "https://data.geopf.fr/telechargement/resource/ADMINEXPRESS-COG"
    "/ADMINEXPRESS-COG/latest?format=GPKG&projection=EPSG:4326"
)
ADMINEXPRESS_GPKG_CACHE = Path(".adminexpress_cache.gpkg")


async def fetch_map_data(
    pmtiles_path: Path = PMTILES_PATH,
    departements_path: Path = DEPARTEMENTS_GEOJSON_PATH,
) -> None:
    """
    Genere les contours cartographiques si absents ou trop anciens :
      - communes.pmtiles : tuiles vectorielles, chargees paresseusement par le
        navigateur en fonction du viewport (au lieu d'un GeoJSON complet de
        35 000 communes charge d'un coup - voir CLAUDE.md "Rendu cartographique"
        pour les mesures memoire qui ont motive cette architecture)
      - departements.geojson : petit fichier (101 features), pas besoin de tuilage

    Stratégie :
      1. Télécharger les contours IGN via geo.api.gouv.fr par département
      2. Simplifier (mapshaper) puis tuiler (tippecanoe) -> communes.pmtiles
      3. Dissoudre les communes par département (mapshaper) -> departements.geojson
    """
    if pmtiles_path.exists() and departements_path.exists():
        age_days = (time.time() - pmtiles_path.stat().st_mtime) / 86400
        if age_days < MAP_DATA_MAX_AGE_DAYS:
            print(
                f"Contours valides ({age_days:.0f}j < {MAP_DATA_MAX_AGE_DAYS}j) : "
                f"{pmtiles_path} ({pmtiles_path.stat().st_size / 1024 / 1024:.1f} Mo)"
            )
            return
        print(f"Contours expires ({age_days:.0f}j), regeneration...")
    else:
        print("Contours absents, generation...")

    if not _check_mapshaper():
        print("  ATTENTION : mapshaper non trouve. Installez-le avec : npm install -g mapshaper")
        print("  Les contours ne seront pas generes - la carte ne s'affichera pas correctement.")
        return
    if not _check_tippecanoe():
        print("  ATTENTION : tippecanoe non trouve. Installez-le avec : apt install tippecanoe")
        print("  Les contours ne seront pas generes - la carte ne s'affichera pas correctement.")
        return

    # API geo.api.gouv.fr département par département (géométries IGN)
    print("  Telechargement des contours communes depuis geo.api.gouv.fr (géom. IGN)...")
    all_features = []
    total_depts = len(ALL_DEPT_CODES)
    errors = []
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
            errors.append(dept)
            print(f"\n  ERREUR dept {dept}: {e}")
        print(
            f"  [{i+1:3d}/{total_depts}] dept {dept:>3} "
            f"| {len(all_features)} communes",
            end="\r",
        )
        time.sleep(0.05)

    if errors:
        print(f"\n  {len(errors)} dept(s) en erreur : {errors}")

    print(f"\n  {len(all_features)} communes téléchargées")
    geojson = {"type": "FeatureCollection", "features": all_features}
    with open(GEOJSON_TMP_PATH, "w", encoding="utf-8") as f:
        json.dump(geojson, f)

    codes = sorted(f["properties"]["code"] for f in all_features)
    with open(COMMUNES_INDEX_PATH, "w", encoding="utf-8") as f:
        json.dump(codes, f)

    # Simplification (mapshaper) puis tuilage vectoriel (tippecanoe) -> PMTiles.
    # "code" (INSEE) est promu comme id de feature côté frontend (promoteId) pour
    # joindre le provider via map.setFeatureState() sans reconstruire les tuiles
    # à chaque mise à jour de data.json (géométrie et classification DNS évoluent
    # à des rythmes très différents).
    print("  Simplification (mapshaper)...")
    simplify_cmd = [
        "mapshaper", str(GEOJSON_TMP_PATH),
        "-simplify", "8%", "weighted", "keep-shapes",
        "-o", "format=geojson", str(GEOJSON_SIMPLIFIED_TMP_PATH),
    ]
    result = subprocess.run(simplify_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERREUR mapshaper (simplify) : {result.stderr}")
        GEOJSON_TMP_PATH.unlink(missing_ok=True)
        return

    print("  Tuilage vectoriel (tippecanoe)...")
    tippecanoe_cmd = [
        "tippecanoe", "-o", str(pmtiles_path), "--force",
        "-l", "communes",
        "-Z4", "-z14",
        "--extend-zooms-if-still-dropping",
        # Sans ça, tippecanoe sur-simplifie/droppe des features pour respecter la
        # limite par defaut de 500 Ko/tuile. A bas zoom, une tuile qui couvre une
        # region dense (ex: tout sauf l'ouest, ~19 000 communes) se retrouvait
        # degradee a des polygones a 4 points (triangles/rectangles visibles a
        # l'oeil nu) pour tenir dans cette limite. On privilegie la fidelite
        # geometrique : le fichier est plus gros mais reste charge par tuile/viewport.
        "--no-tile-size-limit",
        "--no-feature-limit",
        str(GEOJSON_SIMPLIFIED_TMP_PATH),
    ]
    result = subprocess.run(tippecanoe_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERREUR tippecanoe : {result.stderr}")
    else:
        size_mb = pmtiles_path.stat().st_size / 1024 / 1024
        print(f"  PMTiles genere : {pmtiles_path} ({size_mb:.1f} Mo)")

    # Départements : dissolution des communes par préfixe INSEE. Petit fichier
    # (101 features), pas besoin de tuilage, chargé tel quel par le frontend.
    print("  Dissolution departements (mapshaper)...")
    dissolve_cmd = [
        "mapshaper", str(GEOJSON_TMP_PATH),
        "-each",
        "this.properties.dept = (this.properties.code.startsWith('97') || "
        "this.properties.code.startsWith('98')) ? this.properties.code.slice(0,3) "
        ": this.properties.code.slice(0,2)",
        "-dissolve", "dept",
        "-simplify", "10%", "weighted", "keep-shapes",
        "-o", "format=geojson", str(departements_path),
    ]
    result = subprocess.run(dissolve_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ERREUR mapshaper (dissolve departements) : {result.stderr}")
    else:
        size_kb = departements_path.stat().st_size / 1024
        print(f"  Departements generes : {departements_path} ({size_kb:.0f} Ko)")

    GEOJSON_TMP_PATH.unlink(missing_ok=True)
    GEOJSON_SIMPLIFIED_TMP_PATH.unlink(missing_ok=True)


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

            break  # Un seul fichier JSON local dans l'archive

    print(f"  {len(communes)} mairies extraites")
    return communes


DILA_API_URL = (
    "https://api-lannuaire.service-public.gouv.fr/api/explore/v2.1"
    "/catalog/datasets/api-lannuaire-administration/records"
)


async def enrich_missing_websites(
    communes: dict[str, dict],
    concurrency: int = 20,
) -> int:
    """
    Pour les communes sans site web ni email, interroge l'API DILA live
    par code INSEE pour récupérer site_internet et formulaire_contact.
    Retourne le nombre de communes enrichies.
    """
    missing = [
        m for m in communes.values()
        if not m.get("website") and not m.get("contact_email")
    ]
    if not missing:
        return 0

    print(f"\nEnrichissement DILA API pour {len(missing)} communes sans site/email...")
    enriched = 0
    semaphore = asyncio.Semaphore(concurrency)

    async def _fetch_one(client: httpx.AsyncClient, m: dict) -> None:
        nonlocal enriched
        insee = m["insee"]
        url = (
            f"{DILA_API_URL}?where=pivot%20like%20%27mairie%27"
            f"%20AND%20code_insee_commune%3D%27{insee}%27"
            f"&select=site_internet,adresse_courriel,formulaire_contact&limit=1"
        )
        async with semaphore:
            try:
                r = await client.get(url, timeout=10)
                data = r.json()
                results = data.get("results", [])
                if not results:
                    return
                rec = results[0]

                # Site web
                sites = rec.get("site_internet") or []
                if isinstance(sites, list) and sites:
                    website = sites[0].get("valeur", "").strip()
                elif isinstance(sites, str):
                    website = sites.strip()
                else:
                    website = ""

                # Email
                emails = rec.get("adresse_courriel") or []
                if isinstance(emails, list) and emails:
                    email = emails[0].strip()
                elif isinstance(emails, str):
                    email = emails.strip()
                else:
                    email = ""

                # Formulaire contact comme fallback site
                formulaire_raw = rec.get("formulaire_contact") or ""
                formulaire = (
                    formulaire_raw[0].strip() if isinstance(formulaire_raw, list) and formulaire_raw
                    else str(formulaire_raw).strip()
                )

                if not website and formulaire:
                    website = formulaire

                if website or email:
                    if website:
                        m["website"] = website
                    if email:
                        m["contact_email"] = email
                    enriched += 1
            except Exception:
                pass

    async with httpx.AsyncClient(
        headers={"User-Agent": "mxmap.fr/1.0"},
        follow_redirects=True,
    ) as client:
        await asyncio.gather(*[_fetch_one(client, m) for m in missing])

    print(f"  {enriched} communes enrichies via API DILA live")
    return enriched


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
        departement = row.get("departementLabel", {}).get("value", "")
        region = row.get("regionLabel", {}).get("value", "")
        if insee not in communes:
            communes[insee] = {
                "insee": insee, "name": name,
                "departement": departement, "region": region, "contact_email": "",
            }

    print(f"  {len(communes)} communes depuis Wikidata")
    return communes


def _build_entry(m: dict, domain: str, mx: list, spf: str, provider: str, gateway) -> dict[str, Any]:
    """Construit l'entrée de résultat pour une commune."""
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
    if m.get("contact_email"):
        entry["contact_email"] = m["contact_email"]
    if gateway:
        entry["gateway"] = gateway
    if m.get("_dila_email_error"):
        entry["_dila_email_error"] = True
    return entry



def _detect_webmail_app(check: str) -> str | None:
    for app, sigs in WEBMAIL_APPS.items():
        if any(s.lower() in check for s in sigs):
            return app
    return None


async def _probe_webmail_domain(
    client: httpx.AsyncClient,
    domain: str,
) -> dict[str, str] | None:
    """Probe mail./webmail. et chemins connus pour détecter le logiciel webmail.
    Retourne dict(provider, webmail?, _webmail_detected) ou None.
    OWA retourne provider='microsoft' — la distinction on-prem/cloud se fait ensuite via MX.
    Appelé depuis l'intérieur du semaphore de scan_commune — pas de semaphore propre.
    """
    urls: list[tuple[str, str | None]] = []
    for scheme in ("https", "http"):
        urls.append((f"{scheme}://mail.{domain}", None))
        urls.append((f"{scheme}://webmail.{domain}", None))
        urls.append((f"{scheme}://owa.{domain}", None))
        for path, hint in WEBMAIL_PROBES:
            urls.append((f"{scheme}://{domain}{path}", hint))

    for url, hint in urls:
            try:
                r = await client.get(url, timeout=3)
                if r.status_code not in (200, 401, 403):
                    continue
                body = r.text.lower()[:4000]
                final_url = str(r.url).lower()
                check = body + " " + final_url
                app = _detect_webmail_app(check)

                if hint == "microsoft":
                    if not (app == "owa" or "/owa" in final_url or "x-owa-version" in check
                            or "owaauth" in check or "fba," in check):
                        continue
                    return {"provider": "microsoft", "webmail": "owa", "_webmail_detected": url}
                elif hint in ("bluemind", "zimbra"):
                    return {"provider": hint, "webmail": hint, "_webmail_detected": url}
                elif hint == "local":
                    return {"provider": "independent", "webmail": "roundcube", "_webmail_detected": url}
                elif hint:
                    return {"provider": hint, "_webmail_detected": url}

                if app:
                    if app == "owa":
                        return {"provider": "microsoft", "webmail": "owa", "_webmail_detected": url}
                    elif app in ("zimbra", "bluemind"):
                        return {"provider": app, "webmail": app, "_webmail_detected": url}
                    elif app in ("roundcube", "sogo", "horde", "rainloop", "afterlogic",
                                 "open-xchange", "kerio", "icewarp", "mailo"):
                        return {"provider": "independent", "webmail": app, "_webmail_detected": url}
            except Exception:
                continue
    return None


async def scan_commune(
    m: dict[str, str],
    semaphore: asyncio.Semaphore,
    http_client: httpx.AsyncClient,
) -> dict[str, Any]:
    async with semaphore:
        site_domain = url_to_domain(m.get("website", ""))
        contact_email = m.get("contact_email", "")
        email_domain = (
            contact_email.split("@")[1].lower().strip()
            if contact_email and "@" in contact_email
            else ""
        )

        def _normalize(d: str) -> str:
            return d.replace("-", "").lower() if d else ""

        def _root(d: str) -> str:
            parts = d.rstrip(".").split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d

        # Étape 1 : providers identifiables par domaine (0 réseau)
        # @orange.fr, @sfr.fr, @gmail.com, @ovh.net… — pas de probe HTTP, 0 lookup DNS
        if email_domain:
            direct = classify_from_mx([email_domain])
            if direct and direct not in ("independent", "local"):
                return _build_entry(m, email_domain, [], "", direct, None)

        # Étape 2 [PRIORITÉ #1] : probe HTTP mail./webmail./etc. — signal le plus fiable
        # Détecte le logiciel réel avant tout lookup DNS, évite les faux positifs de gateway.
        # Email domain d'abord, site domain si rien trouvé. Domaines FAI/mutualisés exclus.
        probe_domain = ""
        probe_info: dict | None = None
        for candidate in [d for d in [email_domain, site_domain] if d and d not in SHARED_EMAIL_DOMAINS]:
            result = await _probe_webmail_domain(http_client, candidate)
            if result:
                probe_domain = candidate
                probe_info = result
                break

        # Résultat non-OWA : vérité terrain, retour immédiat sans DNS
        if probe_info and probe_info["provider"] not in ("microsoft", "exchange"):
            entry = _build_entry(m, probe_domain, [], "", probe_info["provider"], None)
            if probe_info.get("webmail"):
                entry["webmail"] = probe_info["webmail"]
            if probe_info.get("_webmail_detected"):
                entry["_webmail_detected"] = probe_info["_webmail_detected"]
            return entry

        # OWA détecté : faire quand même le MX pour distinguer on-prem vs cloud, puis retour
        if probe_info:
            mx = await lookup_mx(probe_domain)
            spf = await lookup_spf(probe_domain) if mx else ""
            spf_resolved = await resolve_spf_includes(spf) if spf else ""
            mx_cnames = await resolve_mx_cnames(mx) if mx else {}
            mx_asns = await resolve_mx_asns(mx) if mx else set()
            autodiscover = await lookup_autodiscover(probe_domain)
            is_onprem = bool(mx) and all(_root(h) == _root(probe_domain) for h in mx)
            webmail = "owa-onprem" if is_onprem else "owa"
            provider = "exchange" if is_onprem else "microsoft"
            entry = _build_entry(m, probe_domain, mx, spf, provider, detect_gateway(mx) if mx else None)
            entry["webmail"] = webmail
            entry["_webmail_detected"] = probe_info.get("_webmail_detected", "")
            if spf_resolved and spf_resolved != spf:
                entry["spf_resolved"] = spf_resolved
            if mx_cnames:
                entry["mx_cnames"] = mx_cnames
            if mx_asns:
                entry["mx_asns"] = sorted(mx_asns)
            if autodiscover:
                entry["autodiscover"] = autodiscover
            return entry

        # Étape 3+ : cascade DNS (probe HTTP n'a rien trouvé)
        domain = ""
        mx: list[str] = []
        spf = ""

        if email_domain:
            mx = await lookup_mx(email_domain)
            if mx:
                domain = email_domain
                spf = await lookup_spf(email_domain)

        email_domain_had_no_mx = bool(email_domain and not mx)

        if not mx and site_domain and _normalize(site_domain) != _normalize(email_domain):
            direct = classify_from_mx([site_domain])
            if direct and direct not in ("independent", "local"):
                entry = _build_entry(m, site_domain, [], "", direct, None)
                if email_domain_had_no_mx:
                    entry["_dila_email_error"] = True
                return entry
            mx = await lookup_mx(site_domain)
            if mx:
                domain = site_domain
                spf = await lookup_spf(site_domain)
                if email_domain_had_no_mx:
                    m["_dila_email_error"] = True

        if not mx:
            already_tried = {email_domain, site_domain} - {""}
            for guess in guess_domains(m["name"]):
                if guess in already_tried:
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
        if domain:
            domain_root = _root(domain)
            if mx and all(_root(h) == domain_root for h in mx):
                spf_check = (spf + " " + (spf_resolved or "")).lower()
                if any(k in spf_check for k in ["zimbra", "alpi40.fr", "zcs."]):
                    provider = "zimbra"
                else:
                    provider = "local"
        gateway = detect_gateway(mx) if mx else None
        entry = _build_entry(m, domain, mx, spf, provider, gateway)
        if spf_resolved and spf_resolved != spf:
            entry["spf_resolved"] = spf_resolved
        if mx_cnames:
            entry["mx_cnames"] = mx_cnames
        if mx_asns:
            entry["mx_asns"] = sorted(mx_asns)
        if autodiscover:
            entry["autodiscover"] = autodiscover
        return entry


async def run(output_path: Path) -> None:
    # Générer les contours cartographiques si nécessaire (PMTiles communes + GeoJSON départements)
    await fetch_map_data()

    communes = await fetch_dila()

    # Enrichir les communes sans site web ni email via l'API DILA live
    await enrich_missing_websites(communes)

    wikidata = await fetch_wikidata()
    added_from_wikidata = 0
    for insee, c in wikidata.items():
        if insee not in communes:
            communes[insee] = c
            added_from_wikidata += 1

    if added_from_wikidata:
        print(f"  {added_from_wikidata} communes ajoutees depuis Wikidata (fallback)")

    total = len(communes)
    print(f"\nScan MX/SPF/webmail de {total} communes...")
    print("(Quelques minutes avec les lookups asynchrones + probes HTTP)\n")
    results: dict[str, Any] = {}
    done = 0
    semaphore = asyncio.Semaphore(CONCURRENCY)
    async with httpx.AsyncClient(
        headers={"User-Agent": "mxmap.fr/1.0 (https://github.com/yohannes-git/mxmap-fr)"},
        follow_redirects=True,
        verify=False,
    ) as http_client:
        tasks = [scan_commune(m, semaphore, http_client) for m in communes.values()]
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

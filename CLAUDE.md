# MXmap France - Guide pour Claude

## Contexte du projet

Fork de [mxmap.ch](https://mxmap.ch) adapté pour les ~35 000 communes françaises.
Carte interactive montrant quel hébergeur gère la messagerie officielle de chaque commune française,
à partir de l'analyse DNS publique des enregistrements MX et SPF.

Code source : https://github.com/yohannes-git/mxmap-fr

---

## Architecture

### Pipeline en 3 étapes

```
uv run preprocess   # ~60-90 min  (DNS + probe HTTP webmail en parallèle)
uv run postprocess  # ~10-15 min  (overrides, DNS retry, SMTP, scraping)
uv run validate     # ~1 min
npx serve           # ⚠️ PAS `python3 -m http.server` - voir note ci-dessous
```

**⚠️ `communes.pmtiles` nécessite un serveur qui supporte les requêtes HTTP Range**
(byte serving). `python3 -m http.server` ne les supporte pas (renvoie toujours `200`
avec le fichier entier au lieu de `206 Partial Content`) : la carte des communes
n'affichera aucune donnée. Utiliser `npx serve` (ou n'importe quel serveur/CDN qui
gère `Range`) en local comme en production.

### Fichiers clés

| Fichier | Rôle |
|---|---|
| `src/mail_sovereignty/constants.py` | Keywords providers, gateways, FAI, hébergeurs régionaux |
| `src/mail_sovereignty/classify.py` | Logique de classification MX/SPF/CNAME/ASN |
| `src/mail_sovereignty/preprocess.py` | Téléchargement DILA + probe HTTP webmail (priorité #1) + scan DNS 35 000 communes |
| `src/mail_sovereignty/postprocess.py` | Overrides manuels, retry DNS, SMTP, scraping (plus de probe webmail) |
| `src/mail_sovereignty/validate.py` | Scoring 0-100, quality gate |
| `src/mail_sovereignty/smtp.py` | Vérification banner SMTP port 25 |
| `index.html` | Frontend MapLibre GL |
| `data.json` | Données générées (ne pas éditer manuellement) |
| `communes.pmtiles` | Tuiles vectorielles des contours communaux (généré automatiquement) |
| `departements.geojson` | Contours départementaux, pré-calculés côté serveur (généré automatiquement) |
| `communes-index.json` | Liste plate des codes INSEE couverts par `communes.pmtiles` (debug uniquement) |

---

## Rendu cartographique

Les contours communaux sont servis en **tuiles vectorielles PMTiles** (`communes.pmtiles`),
chargées paresseusement par le navigateur en fonction du viewport, au lieu d'un GeoJSON complet
des 35 000 communes chargé d'un coup. Ce choix vient d'un profiling mémoire réel (Chromium
headless + mesure RSS du process renderer) :

| Approche | RAM navigateur (vue nationale) |
|---|---|
| GeoJSON complet (`type: 'geojson'`, ancienne version) | ~1070-1100 Mo, quel que soit `maxzoom`/`tolerance` réglés sur la source |
| PMTiles (`type: 'vector'`, actuel) | ~450-500 Mo au chargement initial, monte progressivement avec la navigation (cache de tuiles LRU borné) |

Point important découvert pendant ce profiling : régler `maxzoom`/`tolerance` sur une source
GeoJSON ne réduit **pas** la mémoire pour ce jeu de données - MapLibre garde le GeoJSON décodé en
entier en mémoire (thread principal + worker de tuilage), quelle que soit la profondeur de la
pyramide de tuiles. Le seul levier qui fonctionne avec une source GeoJSON est de réduire le
nombre de points de la géométrie elle-même (simplification mapshaper plus agressive). Passer à de
vraies tuiles vectorielles pré-calculées supprime le problème à la racine : le navigateur ne
charge que la zone visible.

### Séparation géométrie / classification

`communes.pmtiles` ne contient **que** la géométrie + `code` (INSEE) + `nom`. Le provider (issu
de `data.json`, qui change à chaque run DNS) n'est **pas** gravé dans les tuiles - il est joint
côté client via `map.setFeatureState()` après un `promoteId: 'code'` sur la source vectorielle.
Ça découple deux cycles de vie très différents : la géométrie (stable, régénérée tous les 30 jours)
et la classification DNS (régénérée à chaque `uv run preprocess`/`postprocess`). Si le provider
était gravé dans les tuiles, il faudrait retuiler (`tippecanoe`, ~1-2 min) à chaque run du pipeline.

`departements.geojson` (101 features dissoutes par préfixe INSEE) reste un GeoJSON classique
chargé tel quel - trop petit pour justifier des tuiles.

### Communes déléguées/associées (doublons commune nouvelle)

La DILA référence chaque ancienne mairie (fusionnée dans une commune nouvelle) sous son propre
code INSEE historique (ex : `01039` Béon, "Mairie déléguée - Béon"), alors que
`geo.api.gouv.fr` ne fournit de géométrie que pour la commune nouvelle issue de la fusion
(ex : `01138` Culoz-Béon). Sans traitement, ces doublons restent dans `data.json` sans jamais
s'afficher sur la carte (aucune géométrie à ce code INSEE) et faussent les compteurs (`counts`,
`total`) en comptant deux fois le même territoire.

`postprocess.py` télécharge la table COG de l'INSEE (`v_commune_YYYY.csv`, colonnes
`TYPECOM`/`COM`/`COMPARENT`, cache local `.cog_cache.csv`, ~30 jours) pour identifier les codes
`COMD`/`COMA` (communes déléguées/associées) et leur commune de rattachement. Toute entrée dont
le code INSEE est une commune déléguée/associée **et** dont la commune de rattachement a déjà sa
propre entrée dans `data.json` est retirée. Millésime de l'URL COG à mettre à jour ~1x/an (nouvelles
fusions de communes effectives au 1er janvier) - voir data.gouv.fr "Code officiel géographique (COG)".

Les codes qui restent sans géométrie après ce filtre sont des communes réelles (`TYPECOM=COM`)
non couvertes par `geo.api.gouv.fr` : Polynésie française, Nouvelle-Calédonie, Saint-Pierre-et-
Miquelon, Saint-Barthélemy, Saint-Martin - un gap de couverture géographique, pas un doublon.

---

## Sources de données

- **Mairies** : Archive DILA (~350 Mo, cache 23h dans `.dila_cache.tar.bz2`)
  URL : `https://lecomarquage.service-public.gouv.fr/donnees_locales_v4/all_latest.tar.bz2`
- **Contours communaux** : API geo.api.gouv.fr par département (101 requêtes), simplifiés
  (mapshaper) puis tuilés (tippecanoe) en `communes.pmtiles`
- **Enrichissement** : API DILA live pour les communes sans site web ni email

---

## Providers détectés

### Grandes plateformes
| Provider | Clé | Description |
|---|---|---|
| `microsoft` | `microsoft` | Microsoft 365 (MX `*.mail.protection.outlook.com`) |
| `exchange` | `exchange` | Exchange On-Prem (OWA sur domaine local) |
| `google` | `google` | Google Workspace |
| `aws` | `aws` | Amazon AWS SES |
| `yahoo` | `yahoo` | Yahoo Mail |

### Hébergeurs FR/EU
| Provider | Clé |
|---|---|
| OVHcloud | `ovh` |
| Gandi | `gandi` |
| IONOS (1&1) | `ionos` |
| Infomaniak | `infomaniak` |
| BlueMind | `bluemind` |
| Zimbra | `zimbra` (backend uniquement — rendu visuellement comme `independent`) |
| Autres / Indépendant | `independent` |

### FAI français
| Provider | Clé |
|---|---|
| Orange / Wanadoo | `orange` |
| SFR / Neuf / Cegetel | `sfr` |
| Free / Alice / Tiscali | `free` |
| Bouygues Telecom | `bouygues` |

### Catégories internes (fusionnées visuellement avec `independent`)
- `local` : MX sur le même domaine racine que la commune (auto-hébergé)
- `french-isp` : Détecté via ASN réseau français

---

## Structure de data.json

```json
{
  "generated": "2025-01-01T00:00:00",
  "counts": {"microsoft": 5662, "ovh": 6535, ...},
  "communes": {
    "44217": {
      "insee": "44217",
      "name": "Mairie - Vigneux-de-Bretagne",
      "departement": "Loire-Atlantique",
      "region": "Pays de la Loire",
      "domain": "vigneuxdebretagne.fr",
      "mx": ["vigneuxdebretagne-fr.mail.protection.outlook.com"],
      "spf": "v=spf1 include:spf.protection.outlook.com ...",
      "provider": "microsoft",
      "sovereignty": "non_eu",
      "contact_email": "[omis]@vigneuxdebretagne.fr",
      "webmail": "owa",
      "gateway": "vadesecure",
      "_dila_email_error": true
    }
  }
}
```

### Champs spéciaux
- `contact_email` : masqué `[omis]@domain.fr` - partie locale retirée avant publication
- `webmail` : interface détectée (`owa`, `zimbra`, `bluemind`, `roundcube`, `sogo`, etc.)
- `gateway` : gateway de filtrage entrant (`vadesecure`, `mimecast`, `hornetsecurity`, etc.)
- `sovereignty` : `"eu"` ou `"non_eu"` — dérivé du provider (voir `NON_EU_CLOUD_PROVIDERS` dans `constants.py`)
- `_dila_email_error` : le domaine email DILA n'a pas de MX, classification basée sur le site web

### Champs internes retirés avant publication (validate.py)
`spf_resolved`, `mx_asns`, `mx_cnames`, `autodiscover`, `_webmail_detected` servent au scoring
(`validate.py`) et au debug pipeline mais ne sont jamais lus par `index.html`. `validate.py` les
retire de `data.json` juste avant la fin du pipeline (après scoring, donc sans impact sur le
quality gate) pour alléger le fichier téléchargé par le navigateur (~35% de réduction).
Pour les inspecter en debug, lire `data.json` juste après `uv run postprocess`, avant `uv run validate`.

---

## Logique de classification (preprocess.py - scan_commune)

Cascade de priorité, du plus fiable au plus générique :

```
1. FAI / providers identifiables par domaine email (0 réseau, 0 ms)
   @orange.fr, @sfr.fr, @free.fr, @bbox.fr, @gmail.com… → retour immédiat

2. [PRIORITÉ #1] Probe HTTP mail./webmail./owa. + chemins connus
   → Email domain d'abord, site domain si rien
   → Domaines FAI/mutualisés exclus (SHARED_EMAIL_DOMAINS)
   → Résultat non-OWA (BlueMind, Zimbra, Roundcube…) → retour immédiat, 0 DNS
   → OWA détecté → lookup MX pour distinguer on-prem vs cloud, puis retour

3. Cascade DNS (probe HTTP vide)
   ├── lookup MX email domain → classify()
   ├── lookup MX site domain (si email domain sans MX)
   └── guess_domains depuis le nom de la commune (dernier recours)
```

URLs testées par le probe HTTP (ordre : https avant http) :
1. `mail.domain`
2. `webmail.domain`
3. `owa.domain`
4. `domain/owa`, `domain/owa/auth/logon.aspx`
5. `domain/zimbra`, `domain/bluemind`
6. `domain/mail`, `domain/webmail`
7. `domain/roundcube`, `domain/roundcubemail`

### Règle "local" (auto-hébergement)
Si TOUS les MX ont le même domaine racine que le domaine testé :
- `relaismail.talmontsainthilaire.fr` → root = `talmontsainthilaire.fr` = domain → **local**
- `mx01.cloud.vadesecure.com` → root = `vadesecure.com` ≠ domain → non local

### Dissociation M365 vs Exchange On-Prem
- Probe HTTP OWA + MX non-local → `microsoft` (cloud M365)
- Probe HTTP OWA + MX sur même domaine racine → `exchange` (on-prem)

---

## Gateways connus (constants.py - GATEWAY_KEYWORDS)

Quand un gateway est détecté en MX, `classify()` regarde derrière via le SPF pour
trouver le vrai hébergeur.

```python
GATEWAY_KEYWORDS = {
    "vadesecure", "mimecast", "hornetsecurity", "barracuda",
    "proofpoint", "sophos", "cisco" (iphmx.com), "altospam",
    "cleanmail", "fortinet", "mailcontrol", "mailinblack", "layer"
}
```

**Cas spécial VadeSecure** : VadeSecure est TOUJOURS un gateway, jamais un hébergeur final.
La logique exclut les domaines gateway du SPF lors de la recherche du provider réel.

---

## Probe webmail HTTP (preprocess.py - _probe_webmail_domain)

Exécuté en **priorité #1** dans `scan_commune`, avant tout lookup DNS.
30 connexions HTTP simultanées (`CONCURRENCY_HTTP`).
Domaines FAI/mutualisés exclus (`SHARED_EMAIL_DOMAINS`).

Signatures détectées (WEBMAIL_APPS + WEBMAIL_PROBES dans constants.py) :
```python
"owa"         → ["owa", "outlook web app", "x-owa-version"]  # + hint /owa
"zimbra"      → ["zimbra", "zcs", "zimbramail"]              # + hint /zimbra
"bluemind"    → ["bluemind", "blue-mind"]                    # + hint /bluemind
"roundcube"   → ["roundcube", "static/login", "rcube"]       # + hint /roundcube
"sogo"        → ["sogo", "/SOGo"]
"rainloop"    → ["rainloop", "snappymail"]
"open-xchange"→ ["appsuite", "open-xchange"]
"kerio"       → ["kerio"]
"mailo"       → ["mailo.com"]
```

---

## Overrides manuels (postprocess.py - MANUAL_OVERRIDES)

Pour les communes absentes de la DILA ou mal classées :

```python
MANUAL_OVERRIDES = {
    "75056": {"name": "Mairie de Paris", "domain": "paris.fr",
              "mx": ["mx1.hc2479-79.eu.iphmx.com"], "provider": "microsoft", "gateway": "cisco"},
    "69123": {"name": "Mairie de Lyon", "domain": "mairie-lyon.fr",
              "mx": ["vade-mx-eu-fallback01.hornetsecurity.com"], "provider": "microsoft", "gateway": "hornetsecurity"},
    "13055": {"name": "Mairie de Marseille", "domain": "marseille.fr",
              "mx": ["de-smtp-inbound-1.mimecast.com"], "provider": "local", "gateway": "mimecast"},
    "85146": {"name": "Mairie - Montaigu-Vendée", "domain": "montaigu-vendee.fr"},
    # Villages morts pour la France (Verdun WW1)
    "55039": {"name": "Beaumont-en-Verdunois", ...},
    ...
}
```

---

## Frontend (index.html)

### Stack technique
- **MapLibre GL** (WebGL, 60fps) - remplace Leaflet
- **PMTiles** (`pmtiles.Protocol`) pour charger `communes.pmtiles` en tuiles vectorielles
  par viewport - voir "Rendu cartographique" plus haut
- **CartoDB Light** comme fond de carte (noms en français)

### Couleurs des providers
```javascript
microsoft:  '#DC2626'  // rouge vif
exchange:   '#B91C1C'  // rouge foncé (Exchange On-Prem)
google:     '#F4B400'  // jaune Google
aws:        '#D97706'  // ambre
ovh:        '#1D4ED8'  // bleu OVH
gandi:      '#0369A1'  // bleu Gandi
ionos:      '#003D8F'  // bleu foncé IONOS
infomaniak: '#0E9E60'  // vert Infomaniak
bluemind:   '#0E7490'  // teal BlueMind
independent:'#0EA5E9'  // bleu ciel (Autres + local + french-isp + zimbra)
orange:     '#FF6600'  // orange officiel
sfr:        '#7C3AED'  // violet SFR
free:       '#DB2777'  // rose Free
bouygues:   '#0891B2'  // cyan Bouygues
unknown:    '#D1D5DB'  // gris pâle
```

### Catégories visuelles
- `local`, `french-isp` et `zimbra` sont affichés avec la couleur de `independent`
- `exchange` suit le filtre `microsoft` dans la légende
- Filtre "Plateformes" : microsoft + exchange + google + aws

---

## Règles importantes

### Ne jamais faire
- Modifier `data.json` manuellement
- Ajouter un provider sans l'ajouter dans `PROVIDER_KEYWORDS`, `classify.py` ET `index.html`
- Mettre VadeSecure comme provider final (toujours gateway)
- Ignorer le champ `webmail` - il est distinct du `provider`

### Ajouter un nouveau provider
1. `constants.py` : ajouter `NEWPROVIDER_KEYWORDS` + dans `PROVIDER_KEYWORDS`
2. `classify.py` : ajouter dans les imports + bloc MX direct + bloc CNAME
3. `index.html` : ajouter dans `COLORS`, `LABELS`, `LEGEND_GROUPS`, `classifyHost`, `darkText`

### Ajouter un gateway
1. `constants.py` : ajouter dans `GATEWAY_KEYWORDS`
2. Relancer `uv run preprocess` (le gateway sera automatiquement détecté)

### Ajouter un override manuel
```python
# Dans postprocess.py - MANUAL_OVERRIDES
"INSEE": {
    "name": "Mairie - NomCommune",
    "departement": "Département",
    "region": "Région",
    "domain": "commune.fr",
    "mx": ["mx.commune.fr"],       # optionnel - si connu
    "provider": "ovh",             # optionnel - si connu
    "gateway": "mimecast",         # optionnel
}
```

---

## Quality Gate (validate.py)

Seuils adaptés à la réalité française :
- Score moyen minimum : **55**
- Haute confiance minimum : **45%**

Le scorer donne des bonus pour :
- `classified_via_known_email_domain` (+70) : domaine FAI connu sans lookup MX (score 95)
- `provider == "local"` : MX auto-hébergé
- `french_regional_hoster` (+10) : hébergeur régional identifié
- `signal_classification` : classifié via autodiscover/SPF sans MX (plafonné à 70)

---

## Prérequis

```bash
npm install -g mapshaper   # simplification géométrie + dissolution départements
sudo apt install tippecanoe  # tuilage vectoriel (génère communes.pmtiles)
uv sync                    # dépendances Python
```

## Commandes utiles

```bash
# Tester scan_commune pour une commune spécifique
uv run python3 -c "
import asyncio, httpx
from mail_sovereignty.preprocess import scan_commune
from mail_sovereignty.constants import CONCURRENCY_HTTP
async def test():
    m = {'insee': '44217', 'name': 'Test', 'website': '', 'departement': '', 'region': '', 'contact_email': 'mairie@test.fr'}
    async with httpx.AsyncClient(follow_redirects=True, verify=False) as http:
        r = await scan_commune(m, asyncio.Semaphore(1), http, asyncio.Semaphore(CONCURRENCY_HTTP))
    print(r['provider'], r['domain'], r['mx'], r.get('webmail'), r.get('_webmail_detected'))
asyncio.run(test())
"

# Vérifier MX d'un domaine
uv run python3 -c "
import asyncio
from mail_sovereignty.dns import lookup_mx, lookup_spf
async def test():
    mx = await lookup_mx('commune.fr')
    spf = await lookup_spf('commune.fr')
    print('MX:', mx)
    print('SPF:', spf)
asyncio.run(test())
"

# Chercher une commune dans data.json
python3 -c "
import json, pprint
with open('data.json') as f: d = json.load(f)
for insee, c in d['communes'].items():
    if 'nomcommune' in c['name'].lower():
        pprint.pprint(c)
"

# Communes sans données (dans communes.pmtiles mais absentes de data.json)
python3 -c "
import json
with open('communes-index.json') as f: codes = json.load(f)
with open('data.json') as f: d = json.load(f)
manquantes = set(codes) - set(d['communes'].keys())
print(len(manquantes), 'communes sans données:', sorted(manquantes))
"

# Top providers
python3 -c "
import json
with open('data.json') as f: d = json.load(f)
for p, n in sorted(d['counts'].items(), key=lambda x: -x[1]):
    print(f'{n:6d}  {p}')
"
```

from mail_sovereignty.constants import (
    AWS_KEYWORDS,
    BLUEMIND_KEYWORDS,
    BOUYGUES_KEYWORDS,
    FOREIGN_SENDER_KEYWORDS,
    FREE_KEYWORDS,
    FRENCH_ISP_ASNS,
    GATEWAY_KEYWORDS,
    GANDI_KEYWORDS,
    GOOGLE_KEYWORDS,
    IONOS_KEYWORDS,
    INFOMANIAK_KEYWORDS,
    LOCAL_TLD_SUFFIXES,
    MICROSOFT_KEYWORDS,
    NON_EU_CLOUD_PROVIDERS,
    ORANGE_KEYWORDS,
    OVH_KEYWORDS,
    PROVIDER_KEYWORDS,
    SFR_KEYWORDS,
    SMTP_BANNER_KEYWORDS,
    VADESECURE_KEYWORDS,
    YAHOO_KEYWORDS,
    ZIMBRA_KEYWORDS,
    FRENCH_REGIONAL_HOSTERS,
)


def classify_sovereignty(provider: str) -> str:
    """Classify data-sovereignty of a provider: "non_eu" (cloud hors UE) ou "eu"."""
    return "non_eu" if provider in NON_EU_CLOUD_PROVIDERS else "eu"


def classify_from_smtp_banner(banner: str, ehlo: str = "") -> str | None:
    """Classify provider from SMTP banner/EHLO. Returns provider or None."""
    if not banner and not ehlo:
        return None
    blob = f"{banner} {ehlo}".lower()
    for provider, keywords in SMTP_BANNER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def classify_from_autodiscover(autodiscover: dict[str, str] | None) -> str | None:
    """Classify provider from autodiscover DNS records."""
    if not autodiscover:
        return None
    blob = " ".join(autodiscover.values()).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def detect_gateway(mx_records: list[str]) -> str | None:
    """Return gateway provider name if MX matches a known gateway, else None."""
    mx_blob = " ".join(mx_records).lower()
    for gateway, keywords in GATEWAY_KEYWORDS.items():
        if any(k in mx_blob for k in keywords):
            return gateway
    return None


def _check_spf_for_provider(spf_blob: str) -> str | None:
    """Check an SPF blob for provider keywords, return provider or None."""
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in spf_blob for k in keywords):
            return provider
    return None


def classify(
    mx_records: list[str],
    spf_record: str | None,
    mx_cnames: dict[str, str] | None = None,
    mx_asns: set[int] | None = None,
    resolved_spf: str | None = None,
    autodiscover: dict[str, str] | None = None,
) -> str:
    """Classify email provider based on MX, CNAME targets, and SPF.

    MX records are checked first (they show where mail is actually delivered).
    CNAME targets of MX hosts are checked next (to detect hidden provider usage).
    If MX points to a known gateway, SPF (including resolved includes) is checked
    to identify the actual mailbox provider behind the gateway.
    SPF is only used as fallback when MX alone is inconclusive.
    """
    mx_blob = " ".join(mx_records).lower()

    # --- Priorité absolue : MX auto-hébergé (même domaine racine) ---
    # Si tous les MX ont le même domaine racine = auto-hébergé, peu importe l'ASN
    # Ex: relaismail.talmontsainthilaire.fr → root = talmontsainthilaire.fr
    # Cette règle doit passer AVANT les checks ASN/keywords
    # Note: classify() ne connaît pas le domaine source, la règle "local" finale
    # dans preprocess.py (_root check) reste le mécanisme principal.
    # Ici on détecte le cas où le MX contient "zimbra" ou "bluemind" explicitement.
    if any(k in mx_blob for k in BLUEMIND_KEYWORDS):
        return "bluemind"
    if any(k in mx_blob for k in ZIMBRA_KEYWORDS):
        return "zimbra"

    # --- Check MX directly ---
    if any(k in mx_blob for k in MICROSOFT_KEYWORDS):
        return "microsoft"
    if any(k in mx_blob for k in GOOGLE_KEYWORDS):
        return "google"
    if any(k in mx_blob for k in OVH_KEYWORDS):
        return "ovh"
    if any(k in mx_blob for k in INFOMANIAK_KEYWORDS):
        return "infomaniak"
    if any(k in mx_blob for k in YAHOO_KEYWORDS):
        return "yahoo"
    if any(k in mx_blob for k in ZIMBRA_KEYWORDS):
        return "zimbra"
    if any(k in mx_blob for k in GANDI_KEYWORDS):
        return "gandi"
    if any(k in mx_blob for k in IONOS_KEYWORDS):
        return "ionos"
    if any(k in mx_blob for k in AWS_KEYWORDS):
        return "aws"
    if any(k in mx_blob for k in ORANGE_KEYWORDS):
        return "orange"
    if any(k in mx_blob for k in FREE_KEYWORDS):
        return "free"
    if any(k in mx_blob for k in SFR_KEYWORDS):
        return "sfr"
    if any(k in mx_blob for k in BOUYGUES_KEYWORDS):
        return "bouygues"

    # --- Check CNAME targets of MX hosts ---
    if mx_records and mx_cnames:
        cname_blob = " ".join(mx_cnames.values()).lower()
        if any(k in cname_blob for k in BLUEMIND_KEYWORDS):
            return "bluemind"
        if any(k in cname_blob for k in MICROSOFT_KEYWORDS):
            return "microsoft"
        if any(k in cname_blob for k in GOOGLE_KEYWORDS):
            return "google"
        if any(k in cname_blob for k in OVH_KEYWORDS):
            return "ovh"
        if any(k in cname_blob for k in INFOMANIAK_KEYWORDS):
            return "infomaniak"
        if any(k in cname_blob for k in YAHOO_KEYWORDS):
            return "yahoo"
        if any(k in cname_blob for k in GANDI_KEYWORDS):
            return "gandi"
        if any(k in cname_blob for k in IONOS_KEYWORDS):
            return "ionos"
        if any(k in cname_blob for k in AWS_KEYWORDS):
            return "aws"
        if any(k in cname_blob for k in ORANGE_KEYWORDS):
            return "orange"
        if any(k in cname_blob for k in FREE_KEYWORDS):
            return "free"
        if any(k in cname_blob for k in SFR_KEYWORDS):
            return "sfr"
        if any(k in cname_blob for k in BOUYGUES_KEYWORDS):
            return "bouygues"

    # --- MX points to a known security gateway: look behind it via SPF/autodiscover ---
    if mx_records and detect_gateway(mx_records):
        gw = detect_gateway(mx_records)
        spf_blob = (spf_record or "").lower()
        resolved_blob = (resolved_spf or "").lower()

        # BlueMind/Zimbra en priorité : gateway devant BlueMind/Zimbra = self-hosted
        if any(k in spf_blob or k in resolved_blob for k in BLUEMIND_KEYWORDS):
            return "bluemind"
        if any(k in spf_blob or k in resolved_blob for k in ZIMBRA_KEYWORDS):
            return "zimbra"

        # Chercher le provider réel dans le SPF, en excluant le gateway lui-même
        # Ex: VadeSecure dans le SPF ne doit pas être retourné comme provider final
        GATEWAY_DOMAINS = {k for keywords in GATEWAY_KEYWORDS.values() for k in keywords}
        def _check_spf_exclude_gateway(blob: str) -> str | None:
            for provider, keywords in PROVIDER_KEYWORDS.items():
                for k in keywords:
                    if k in blob and k not in GATEWAY_DOMAINS:
                        return provider
            return None

        provider = _check_spf_exclude_gateway(spf_blob)
        if not provider:
            provider = _check_spf_exclude_gateway(resolved_blob)
        if provider:
            return provider

        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider

        # Domaine .fr = hébergement local derrière le gateway
        if spf_blob and any(s in spf_blob for s in LOCAL_TLD_SUFFIXES):
            return "local"

        # Gateway connu mais provider final non identifiable → retourner le gateway
        return gw
        # Gateway relays to independent, fall through

    # --- MX exists but no known provider matched ---
    if mx_records:
        if mx_asns and mx_asns & FRENCH_ISP_ASNS.keys():
            ad_provider = classify_from_autodiscover(autodiscover)
            if ad_provider:
                return ad_provider
            asn_match = mx_asns & FRENCH_ISP_ASNS.keys()
            asn = next(iter(asn_match))
            isp_name = FRENCH_ISP_ASNS[asn].lower()
            if "orange" in isp_name or "wanadoo" in isp_name:
                return "orange"
            if "free" in isp_name or "iliad" in isp_name:
                return "free"
            if "sfr" in isp_name or "numericable" in isp_name or "cegetel" in isp_name:
                return "sfr"
            if "bouygues" in isp_name:
                return "bouygues"
            return "french-isp"
        ad_provider = classify_from_autodiscover(autodiscover)
        if ad_provider:
            return ad_provider
        # Hébergeur régional français identifié = independent (prestataire local connu)
        if any(h in " ".join(mx_records).lower() for h in FRENCH_REGIONAL_HOSTERS):
            return "independent"
        return "independent"

    # --- No MX: fall back to SPF ---
    # Note: "local" est attribué dans preprocess via classify_from_mx sur le domaine email
    spf_blob = (spf_record or "").lower()
    provider = _check_spf_for_provider(spf_blob)
    if not provider and resolved_spf:
        provider = _check_spf_for_provider(resolved_spf.lower())
    if provider:
        return provider

    return "unknown"


def classify_from_mx(mx_records: list[str]) -> str | None:
    """Classify provider from MX records alone."""
    if not mx_records:
        return None
    blob = " ".join(mx_records).lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    # Un domaine .fr non reconnu reste "independent" ici -
    # la catégorie "local" est attribuée par classify() après lookup MX
    return "independent"


def classify_from_spf(spf_record: str | None) -> str | None:
    """Classify provider from SPF record alone."""
    if not spf_record:
        return None
    blob = spf_record.lower()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            return provider
    return None


def spf_mentions_providers(spf_record: str | None) -> set[str]:
    """Return set of providers mentioned in SPF (main + foreign senders)."""
    if not spf_record:
        return set()
    blob = spf_record.lower()
    found = set()
    for provider, keywords in PROVIDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    for provider, keywords in FOREIGN_SENDER_KEYWORDS.items():
        if any(k in blob for k in keywords):
            found.add(provider)
    return found

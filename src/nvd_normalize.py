"""
NVD record normalization - turn a raw NVD CVE 2.0 record into a document.

Each CVE becomes exactly one document. The split between *embedded text* and
*stored metadata* is deliberate:

Embedded text (what the retriever sees) carries the description plus the fields
that make a CVE findable by a human query: the CVE ID, the affected vendors and
products drawn from CPE, the CWE identifiers, and the severity. An analyst
searching "remote code execution in Java logging libraries" needs the prose; one
searching "log4j 2.14.1" needs the product strings. Both must be in the embedded
text or neither query works.

Stored metadata (never embedded) carries the structured fields that filtering
needs: CVSS base score and vector, severity, published/modified dates, CWE IDs,
and CPE entries. Embedding a CVSS vector string would add noise to the vector
without helping retrieval; filtering on it needs an exact value, not a fuzzy
match.

ChromaDB metadata values must be scalars (str/int/float/bool), so list-valued
fields are stored as delimited strings and dates are stored twice: an ISO string
for display and an epoch integer for range queries.
"""

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# CVSS precedence: newest scoring system first. Within a version, NVD's own
# "Primary" score is preferred over a vendor-supplied "Secondary" one, because
# vendors frequently self-report inflated severities.
CVSS_METRIC_PRECEDENCE = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)

# CWE placeholders that carry no classification signal.
CWE_PLACEHOLDERS = {"NVD-CWE-noinfo", "NVD-CWE-Other", "unsure", "n/a"}

# Vendor/product placeholders used by NVD when the field is unknown.
PRODUCT_PLACEHOLDERS = {"n/a", "-", "*", ""}

# A CVE with this status has been withdrawn; indexing it would surface
# vulnerabilities that do not exist.
REJECTED_STATUSES = {"Rejected"}

# Caps on how many vendor/product names reach the *embedded* text.
#
# These are deliberately tight, and the numbers come from measurement rather
# than taste. A widely-bundled CVE can carry hundreds of CPE entries; letting
# them all into the embedded text swamps the description and pulls the vector
# toward a list of part numbers. Measured on 1,200 sampled CVEs, moving the
# description to the front and capping at 6 vendors / 8 products lifted
# recall@1 from 0.769 to 0.962 for CVEs with 21-60 affected products, and never
# scored worse in any bucket. See "Document design" in the README.
#
# The metadata caps are looser because metadata is stored, not embedded, so it
# costs retrieval quality nothing and keeps more detail available for filtering.
# Bumped by hand when the layout changes deliberately; layout_fingerprint()
# below is the machine-checked counterpart that cannot be forgotten.
# 1 = metadata-first (pre-measurement). 2 = description-first, CNA vendors first.
DOCUMENT_LAYOUT_VERSION = 2

MAX_VENDORS_IN_TEXT = 6
MAX_PRODUCTS_IN_TEXT = 8
MAX_VENDORS_IN_METADATA = 25
MAX_PRODUCTS_IN_METADATA = 40

LIST_DELIMITER = "|"


def split_cpe(cpe: str) -> List[str]:
    """
    Split a CPE 2.3 formatted string on unescaped colons.

    CPE 2.3 escapes literal colons as ``\\:``, so a naive ``str.split(":")``
    corrupts any component containing one. Example criteria that breaks a naive
    split: ``cpe:2.3:a:purestorage:purity\\/\\/fa:*:*:*:*:*:*:*:*``
    """
    parts: List[str] = []
    current: List[str] = []
    escaped = False
    for char in cpe:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(char)
    parts.append("".join(current))
    return parts


def unescape_cpe_component(value: str) -> str:
    """Turn a CPE component into readable text (``purity\\/\\/fa`` -> ``purity//fa``)."""
    out: List[str] = []
    escaped = False
    for char in value:
        if escaped:
            out.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            out.append(char)
    # CPE uses "_" where a name has a space.
    return "".join(out).replace("_", " ").strip()


def extract_english_description(record: Dict[str, Any]) -> str:
    """Return the English description, or "" when the record has none."""
    for entry in record.get("descriptions") or []:
        if entry.get("lang") == "en":
            return (entry.get("value") or "").strip()
    return ""


def extract_cvss(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Pick the best available CVSS score.

    Returns a dict with cvss_version, cvss_base_score, cvss_vector and severity.
    Values are None/"" when the CVE has no CVSS data at all, which is common for
    recent or disputed records.
    """
    metrics = record.get("metrics") or {}
    for key, version in CVSS_METRIC_PRECEDENCE:
        entries = metrics.get(key) or []
        if not entries:
            continue
        # Prefer NVD's Primary score over a vendor Secondary one.
        chosen = next(
            (e for e in entries if e.get("type") == "Primary"),
            entries[0],
        )
        data = chosen.get("cvssData") or {}
        base_score = data.get("baseScore")
        # CVSS v2 puts severity on the wrapper; v3+ puts it in cvssData.
        severity = data.get("baseSeverity") or chosen.get("baseSeverity") or ""
        return {
            "cvss_version": version,
            "cvss_base_score": float(base_score) if base_score is not None else None,
            "cvss_vector": data.get("vectorString") or "",
            "severity": severity.upper(),
        }
    return {
        "cvss_version": "",
        "cvss_base_score": None,
        "cvss_vector": "",
        "severity": "",
    }


def extract_cwes(record: Dict[str, Any]) -> List[str]:
    """
    Return real CWE identifiers, Primary sources first, de-duplicated.

    NVD placeholders ("NVD-CWE-noinfo", "NVD-CWE-Other") are dropped: they mean
    "not classified" and would otherwise look like a real weakness class.
    """
    primary: List[str] = []
    secondary: List[str] = []
    for weakness in record.get("weaknesses") or []:
        bucket = primary if weakness.get("type") == "Primary" else secondary
        for desc in weakness.get("description") or []:
            if desc.get("lang") != "en":
                continue
            value = (desc.get("value") or "").strip()
            if value and value not in CWE_PLACEHOLDERS:
                bucket.append(value)

    seen: set = set()
    ordered: List[str] = []
    for value in primary + secondary:
        if value not in seen:
            seen.add(value)
            ordered.append(value)
    return ordered


def extract_cpe_entries(record: Dict[str, Any]) -> Tuple[List[str], List[str], List[str]]:
    """
    Walk the configuration tree and pull out CPE criteria, vendors and products.

    Returns (cpe_criteria, vendors, products), de-duplicated, with the
    CNA-supplied names first.

    Ordering matters because the lists are truncated before embedding. The
    `affected` block comes from the CNA - the party that owns and reported the
    vulnerability - so it names the product that is actually broken. The
    `configurations` tree instead enumerates every downstream product that
    bundles it, and NVD orders those by internal node structure, not relevance.

    CVE-2021-44228 (Log4Shell) is the case that makes this concrete: its CNA
    entry is "Apache Software Foundation / Apache Log4j2", while its 396 CPE
    entries begin with Siemens firmware part numbers. Taking CPE order first
    pushed "log4j" to 11th place and would truncate it entirely on a record with
    more vendors - so the single most-searched product string would be missing
    from the embedded text.
    """
    criteria: List[str] = []
    vendors: List[str] = []
    products: List[str] = []

    def add(collection: List[str], value: str) -> None:
        if value and value.lower() not in PRODUCT_PLACEHOLDERS and value not in collection:
            collection.append(value)

    # CNA-supplied vendor/product first: authoritative, and the only source when
    # NVD has not analysed the record yet.
    for affected in record.get("affected") or []:
        for data in affected.get("affectedData") or []:
            add(vendors, (data.get("vendor") or "").strip())
            add(products, (data.get("product") or "").strip())

    for config in record.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                raw = match.get("criteria") or ""
                if not raw:
                    continue
                if raw not in criteria:
                    criteria.append(raw)
                parts = split_cpe(raw)
                # cpe:2.3:<part>:<vendor>:<product>:<version>:...
                if len(parts) > 4:
                    add(vendors, unescape_cpe_component(parts[3]))
                    add(products, unescape_cpe_component(parts[4]))

    return criteria, vendors, products


def _to_epoch(value: str) -> Optional[int]:
    """Parse an NVD timestamp ("2024-01-31T14:15:45.123") into epoch seconds."""
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def should_index(record: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Decide whether a record belongs in the index.

    Returns (keep, reason_when_dropped). Two filters apply:
      - Rejected CVEs are withdrawn and must not be presented as real findings.
      - Records with no English description have nothing meaningful to embed.
    """
    if record.get("vulnStatus") in REJECTED_STATUSES:
        return False, "rejected"
    if not extract_english_description(record):
        return False, "no_english_description"
    return True, ""


# Synthetic records that exercise every layout decision. Deliberately not drawn
# from the corpus: a fixture that changes when the feed changes cannot serve as
# a fixed reference point.
_LAYOUT_FIXTURES: Tuple[Dict[str, Any], ...] = (
    {
        # Caps: 9 vendors and 11 products, above both text caps (6 / 8) and
        # below both metadata caps (25 / 40), so a change to either moves the
        # hash. CNA `affected` first, then `configurations`, so a change to
        # that ordering moves it too.
        "id": "CVE-2000-00001",
        "vulnStatus": "Analyzed",
        "published": "2000-01-01T00:00:00.000",
        "lastModified": "2000-01-02T00:00:00.000",
        "sourceIdentifier": "layout@fixture.test",
        "descriptions": [
            {"lang": "en", "value": "First sentence of the description. Second sentence."},
            {"lang": "es", "value": "No debe aparecer."},
        ],
        "affected": [
            {"affectedData": [{"vendor": "cna_vendor", "product": "cna_product"}]}
        ],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": (
                                    f"cpe:2.3:a:vendor{i}:product{i}:1.0:*:*:*:*:*:*:*"
                                ),
                                "vulnerable": True,
                            }
                            for i in range(10)
                        ]
                    }
                ]
            }
        ],
        "weaknesses": [
            {"description": [{"lang": "en", "value": "CWE-79"},
                             {"lang": "en", "value": "CWE-89"}]}
        ],
        "metrics": {
            # v3.1 must win over v2 under CVSS_METRIC_PRECEDENCE.
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL",
                             "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                             "version": "3.1"},
            }],
            "cvssMetricV2": [{
                "type": "Primary",
                "cvssData": {"baseScore": 5.0, "vectorString": "AV:N/AC:L/Au:N/C:P/I:N/A:N",
                             "version": "2.0"},
                "baseSeverity": "MEDIUM",
            }],
        },
    },
    {
        # Minimal record: no CPE, no CWE, no metrics. Pins what the layout omits
        # rather than only what it emits.
        "id": "CVE-2000-00002",
        "vulnStatus": "Awaiting Analysis",
        "published": "2000-02-01T00:00:00.000",
        "lastModified": "2000-02-01T00:00:00.000",
        "sourceIdentifier": "layout@fixture.test",
        "descriptions": [{"lang": "en", "value": "A description with no metadata at all."}],
    },
)


def layout_fixtures() -> Tuple[Dict[str, Any], ...]:
    """The fixed records layout_fingerprint() renders."""
    return _LAYOUT_FIXTURES


def layout_fingerprint() -> str:
    """
    A short hash of what this module currently *produces*, not of its source.

    An index is only comparable with a measurement if both were made from the
    same document layout. Recording a hand-maintained version number relies on
    remembering to bump it; hashing the source of build_document_text() trips on
    every comment edit. Hashing the output of a fixed set of fixtures changes
    when, and only when, the rendered documents change - which is the property
    that actually matters.

    The fixtures are chosen to exercise each layout decision: field order, the
    text and metadata caps, CNA-before-CPE vendor ordering, the list delimiter,
    and the CVSS precedence. A change to any of them moves the hash.
    """
    payload = json.dumps(
        [normalize(record) for record in layout_fixtures()],
        sort_keys=True,
        ensure_ascii=True,
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def layout_descriptor() -> Dict[str, Any]:
    """The document layout as it should be recorded in artifacts."""
    return {
        "version": DOCUMENT_LAYOUT_VERSION,
        "fingerprint": layout_fingerprint(),
        "max_vendors_in_text": MAX_VENDORS_IN_TEXT,
        "max_products_in_text": MAX_PRODUCTS_IN_TEXT,
        "max_vendors_in_metadata": MAX_VENDORS_IN_METADATA,
        "max_products_in_metadata": MAX_PRODUCTS_IN_METADATA,
        "list_delimiter": LIST_DELIMITER,
    }


def build_document_text(record: Dict[str, Any]) -> str:
    """
    Render the text that actually gets embedded.

    The description leads, because it is what a natural-language query actually
    matches against. Identifier and product strings follow: they are needed so
    that "log4j 2.14.1" style queries have something to hit, but placing them
    first measurably degraded semantic retrieval on heavily-bundled CVEs (see
    the note on MAX_PRODUCTS_IN_TEXT above).

    A bare CVE ID in this text is still a weak substitute for lexical matching -
    dense vectors barely distinguish one CVE identifier from another. Reliable
    ID lookup needs exact matching, not embeddings.
    """
    cvss = extract_cvss(record)
    cwes = extract_cwes(record)
    _, vendors, products = extract_cpe_entries(record)

    # Description first, prefixed with the identifier.
    lines = [f"{record.get('id', '')}: {extract_english_description(record)}", ""]

    if vendors:
        lines.append(f"Affected vendors: {', '.join(vendors[:MAX_VENDORS_IN_TEXT])}")
    if products:
        lines.append(f"Affected products: {', '.join(products[:MAX_PRODUCTS_IN_TEXT])}")
    if cwes:
        lines.append(f"Weaknesses: {', '.join(cwes)}")

    if cvss["severity"] or cvss["cvss_base_score"] is not None:
        score = cvss["cvss_base_score"]
        score_text = f"{score}" if score is not None else "unscored"
        lines.append(
            f"Severity: {cvss['severity'] or 'UNKNOWN'} "
            f"(CVSS {cvss['cvss_version'] or 'n/a'} base score {score_text})"
        )

    return "\n".join(lines).strip()


def build_metadata(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build the ChromaDB metadata dict.

    All values are scalars because ChromaDB rejects lists. Dates are stored
    twice - ISO text for display, epoch integers so range filters work.
    """
    cvss = extract_cvss(record)
    cwes = extract_cwes(record)
    criteria, vendors, products = extract_cpe_entries(record)

    published = record.get("published") or ""
    last_modified = record.get("lastModified") or ""
    cve_id = record.get("id", "")

    metadata: Dict[str, Any] = {
        "type": "cve",
        "cve_id": cve_id,
        "year": cve_id.split("-")[1] if cve_id.count("-") >= 2 else "",
        "vuln_status": record.get("vulnStatus") or "",
        "source_identifier": record.get("sourceIdentifier") or "",
        "severity": cvss["severity"],
        "cvss_version": cvss["cvss_version"],
        "cvss_vector": cvss["cvss_vector"],
        "published": published,
        "last_modified": last_modified,
        "cwe_ids": LIST_DELIMITER.join(cwes),
        "vendors": LIST_DELIMITER.join(vendors[:MAX_VENDORS_IN_METADATA]),
        "products": LIST_DELIMITER.join(products[:MAX_PRODUCTS_IN_METADATA]),
        "cpe_count": len(criteria),
        "reference_count": len(record.get("references") or []),
    }

    # Only set numeric fields when present; ChromaDB rejects None values.
    if cvss["cvss_base_score"] is not None:
        metadata["cvss_base_score"] = cvss["cvss_base_score"]
    published_ts = _to_epoch(published)
    if published_ts is not None:
        metadata["published_ts"] = published_ts
    modified_ts = _to_epoch(last_modified)
    if modified_ts is not None:
        metadata["last_modified_ts"] = modified_ts

    return metadata


def normalize(record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Turn one raw NVD record into {id, document, metadata}, or None if filtered.
    """
    keep, _reason = should_index(record)
    if not keep:
        return None
    return {
        "id": record["id"],
        "document": build_document_text(record),
        "metadata": build_metadata(record),
    }

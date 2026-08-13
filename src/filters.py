"""
Metadata filter specifications, shared by the lexical and dense backends.

An analyst rarely wants "the most similar document in the whole corpus". They
want the most similar document *among CRITICAL findings published this quarter
that affect Apache*. That is a pre-filter: the constraint has to shrink the
candidate set before ranking, not trim the ranked list afterwards. Post-filtering
a top-100 by severity does not return the 100 best CRITICAL matches, it returns
however many of the top 100 happened to be CRITICAL - often far fewer, and
sometimes none, with no signal that anything was dropped.

One filter spec, two translations, because the backends can express different
things:

  severity, year, min_cvss, max_cvss, published_after, published_before
      Scalar fields. Both backends filter these natively - a SQL predicate on
      the FTS metadata table, a `where` clause on the Chroma collection.

  vendor, product, cwe
      Stored as pipe-delimited packed lists ("apache|debian|redhat"). Chroma's
      metadata filtering has no substring or list-membership operator, so these
      cannot be expressed as a `where` clause at all. They are resolved against
      the lexical index - which stores the same packed lists and can match a
      whole element in SQL - into an explicit ID allow-list that Chroma accepts
      via its `ids` parameter.

Using the lexical index as the sole authority for list membership is deliberate.
Two independent implementations of "does this CVE affect Apache" would be two
chances to disagree, and a hybrid query whose arms filter differently produces a
ranking over a candidate set that neither arm actually endorses.

Unknown keys raise. A silently ignored filter key is the exact failure this
module exists to prevent: the caller believes the result is constrained, the
result is not, and nothing in the output says so.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

# Scalar fields both backends can filter natively.
SCALAR_FILTERS: Tuple[str, ...] = (
    "severity",
    "year",
    "min_cvss",
    "max_cvss",
    "published_after",
    "published_before",
    # Exploitation signals (src/exploitation.py). Scalars on both backends.
    "kev",
    "kev_ransomware",
    "min_epss",
    "min_epss_percentile",
)

# Packed-list fields only the lexical index can filter.
LIST_FILTERS: Tuple[str, ...] = ("vendor", "product", "cwe")

ALL_FILTERS: Tuple[str, ...] = SCALAR_FILTERS + LIST_FILTERS

# Chroma metadata keys for the scalar fields, and the operator each maps to.
_CHROMA_RANGE = {
    "min_cvss": ("cvss_base_score", "$gte"),
    "max_cvss": ("cvss_base_score", "$lte"),
    "published_after": ("published_ts", "$gte"),
    "published_before": ("published_ts", "$lte"),
    "min_epss": ("epss_score", "$gte"),
    "min_epss_percentile": ("epss_percentile", "$gte"),
}

# Boolean equality fields.
_CHROMA_BOOL = {"kev": "kev", "kev_ransomware": "kev_ransomware"}


class FilterError(ValueError):
    """Raised when a filter spec is malformed or names an unknown field."""


def validate(filters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Check a filter spec and return it unchanged.

    Raises:
        FilterError: An unknown key, or a range bound that is not a number.
    """
    if not filters:
        return {}
    unknown = sorted(set(filters) - set(ALL_FILTERS))
    if unknown:
        raise FilterError(
            f"unknown filter field(s): {', '.join(unknown)}. "
            f"Supported: {', '.join(ALL_FILTERS)}"
        )
    numeric = ("min_cvss", "max_cvss", "published_after", "published_before",
               "min_epss", "min_epss_percentile")
    for key in numeric:
        if key in filters and not isinstance(filters[key], (int, float)):
            raise FilterError(f"{key} must be a number, got {filters[key]!r}")
    for key in ("min_epss", "min_epss_percentile"):
        if key in filters and not 0.0 <= float(filters[key]) <= 1.0:
            raise FilterError(
                f"{key} is a probability in [0, 1], got {filters[key]!r}. "
                "EPSS scores are not percentages."
            )
    for key in ("kev", "kev_ransomware"):
        if key in filters and not isinstance(filters[key], bool):
            raise FilterError(f"{key} must be true or false, got {filters[key]!r}")
    if "min_cvss" in filters and "max_cvss" in filters:
        if filters["min_cvss"] > filters["max_cvss"]:
            raise FilterError(
                f"min_cvss {filters['min_cvss']} exceeds max_cvss {filters['max_cvss']}; "
                "this matches nothing and is more likely a swapped pair"
            )
    return dict(filters)


def matches_nothing(filters: Optional[Dict[str, Any]]) -> bool:
    """True when the spec is unsatisfiable by construction (an empty allow-list).

    Callers short-circuit on this rather than handing an empty `$in` to a
    backend, because backends disagree about whether that is an error or a
    match-everything.
    """
    if not filters:
        return False
    for key in ("severity", "year"):
        value = filters.get(key)
        if isinstance(value, (list, tuple, set)) and not value:
            return True
    return False


def list_filter_subset(filters: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The part of the spec that only the lexical index can evaluate."""
    return {k: v for k, v in (filters or {}).items() if k in LIST_FILTERS}


def to_chroma_where(filters: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Translate the scalar part of a spec into a Chroma `where` clause.

    The list-valued fields are deliberately absent: Chroma cannot express them,
    and emitting a clause that quietly covers only part of the spec would return
    records outside the filter. Callers must combine this with the ID allow-list
    from resolve_allowlist().
    """
    validate(filters)
    if not filters:
        return None

    conditions: List[Dict[str, Any]] = []
    for key in ("severity", "year"):
        if key in filters:
            value = filters[key]
            if isinstance(value, (list, tuple, set)):
                conditions.append({key: {"$in": list(value)}})
            else:
                conditions.append({key: {"$eq": value}})
    for key, (field, operator) in _CHROMA_RANGE.items():
        if key in filters:
            conditions.append({field: {operator: filters[key]}})
    for key, field in _CHROMA_BOOL.items():
        if key in filters:
            # $eq on the stored boolean. A record that was never enriched has no
            # such key at all, and Chroma does not match a missing key, so an
            # unenriched record cannot satisfy kev=False either - which matches
            # the lexical side's NULL handling.
            conditions.append({field: {"$eq": bool(filters[key])}})

    if not conditions:
        return None
    # Chroma rejects a single-element $and in some versions; pass the bare
    # condition when there is only one.
    return conditions[0] if len(conditions) == 1 else {"$and": conditions}


def resolve_allowlist(conn, filters: Optional[Dict[str, Any]]) -> Optional[List[str]]:
    """
    Resolve the list-valued part of a spec into explicit CVE IDs.

    Returns None when the spec has no list-valued fields, meaning "no allow-list
    needed" - which is different from an empty list, meaning "nothing matches".

    Resolved once per retriever rather than per query: a filter is fixed for the
    life of a retriever, and the underlying scan is the most expensive part of
    filtering (about a second for a vendor matching 26,000 records).
    """
    import lexical_index as LX

    subset = list_filter_subset(filters)
    if not subset:
        return None
    return LX.filter_ids(conn, subset)


def describe(filters: Optional[Dict[str, Any]]) -> str:
    """Human-readable one-liner, for logs and result files."""
    if not filters:
        return "none"
    return ", ".join(f"{k}={v}" for k, v in sorted(filters.items()))

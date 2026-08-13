"""
Lexical (BM25) index over the CVE corpus, backed by SQLite FTS5.

Why FTS5 rather than a pip BM25 package: `rank_bm25` and friends hold the entire
index in memory and score every document on every query. At 358,170 documents
that is both slow and memory-hungry. FTS5 ships with the standard library's
sqlite3, stores its index on disk, and provides a built-in bm25() ranking
function backed by an inverted index, so a query touches only the postings for
the terms it actually contains.

Two tables are built:

  cve_fts   an FTS5 virtual table holding the same text that was embedded into
            ChromaDB, so the lexical and dense arms rank the same content
  cve_meta  a plain table carrying the filterable metadata fields, joined by
            cve_id, so a filtered lexical search is a SQL predicate rather than
            a post-filter that silently shrinks the result set

Sign convention: SQLite's bm25() returns *negative* scores where a more negative
value is a better match. Callers get the negated value so that larger is better,
which is the convention every other component here uses.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

# Tokenizer choice, made by measurement (experiments/fts_tokenizer.py, results in
# experiments/results/fts_tokenizer.json).
#
# The default unicode61 tokenizer treats "-" and "." as separators, so
# CVE-2021-44228 becomes three tokens and 2.14.1 becomes three integers. Adding
# both characters to `tokenchars` keeps each identifier whole.
#
# Measured on a 61,030-document subset, the two tokenizers are indistinguishable
# on accuracy - both reach R@1 0.997 on bare CVE IDs and 0.237 on product +
# version. The difference is latency: because escape_fts_query() emits quoted
# phrases, a hyphenated string under the default tokenizer becomes a multi-token
# phrase requiring position checks on every candidate, while here it is a single
# token lookup. That is 3.2 ms versus 15.4 ms per product query, a 5x gap that
# costs nothing in quality.
TOKENIZER = "unicode61 tokenchars '-.' remove_diacritics 2"

FTS_TABLE = "cve_fts"
META_TABLE = "cve_meta"

# Long queries (the description-sentence control runs to ~35 words) are capped
# so a single query cannot walk the postings list of every common term in the
# corpus. Terms are kept in order, so the cap drops the tail of a sentence
# rather than a random subset.
MAX_QUERY_TERMS = 32

# Metadata columns mirrored from the normalized record for filtering.
META_COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("cve_id", "TEXT PRIMARY KEY"),
    ("severity", "TEXT"),
    ("cvss_base_score", "REAL"),
    ("published_ts", "INTEGER"),
    ("last_modified_ts", "INTEGER"),
    ("year", "TEXT"),
    ("cwe_ids", "TEXT"),
    ("vendors", "TEXT"),
    ("products", "TEXT"),
)


class LexicalIndexError(RuntimeError):
    """Raised when the lexical index is missing or inconsistent."""


def escape_fts_query(text: str, max_terms: int = MAX_QUERY_TERMS) -> str:
    """
    Turn arbitrary user text into a safe FTS5 MATCH expression.

    FTS5 MATCH input is a *query language*, not a string: AND, OR, NOT, NEAR,
    ^, * and quotes are all operators. Passing user text through raw means a
    query containing a stray quote or a bare "AND" either throws
    sqlite3.OperationalError or silently means something other than what the
    user typed. Treat the text as data: split it into terms and wrap each one
    as a quoted string literal, doubling any embedded quote.

    Terms are combined with OR so that bm25() does the ranking. FTS5's implicit
    operator is AND, which for a 35-word sentence would demand every term be
    present and usually match nothing at all.

    Returns "" when the text contains no usable term; callers must treat that
    as "no results" rather than passing it to MATCH.
    """
    # Keep alphanumerics plus the characters the tokenizer treats as word
    # constituents, so the query terms and the indexed tokens agree.
    terms = re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", text)
    if not terms:
        return ""
    quoted = ['"' + term.replace('"', '""') + '"' for term in terms[:max_terms]]
    return " OR ".join(quoted)


def connect(db_path: Path, read_only: bool = False) -> sqlite3.Connection:
    """Open the lexical index database."""
    if read_only:
        if not Path(db_path).exists():
            raise LexicalIndexError(
                f"no lexical index at {db_path}. Build it with: "
                f"python src/build_fts.py"
            )
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    else:
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def create_schema(conn: sqlite3.Connection, tokenizer: str = TOKENIZER) -> None:
    """(Re)create the FTS and metadata tables, dropping any previous build."""
    conn.execute(f"DROP TABLE IF EXISTS {FTS_TABLE}")
    conn.execute(f"DROP TABLE IF EXISTS {META_TABLE}")
    # cve_id is UNINDEXED: it is the key we read back, and the identifier
    # already appears at the head of `document`, so indexing it twice would
    # double-count it in the BM25 term statistics.
    conn.execute(
        f"CREATE VIRTUAL TABLE {FTS_TABLE} USING fts5("
        f"  cve_id UNINDEXED,"
        f"  document,"
        f"  tokenize=\"{tokenizer}\""
        f")"
    )
    columns = ", ".join(f"{name} {decl}" for name, decl in META_COLUMNS)
    conn.execute(f"CREATE TABLE {META_TABLE} ({columns})")
    conn.commit()


def create_metadata_indexes(conn: sqlite3.Connection) -> None:
    """Index the metadata columns that filtering actually uses."""
    for column in ("severity", "cvss_base_score", "published_ts", "year"):
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS idx_{META_TABLE}_{column} "
            f"ON {META_TABLE}({column})"
        )
    conn.commit()


def insert_batch(
    conn: sqlite3.Connection, rows: Sequence[Dict[str, Any]]
) -> None:
    """Insert a batch of normalized records into both tables."""
    conn.executemany(
        f"INSERT INTO {FTS_TABLE}(cve_id, document) VALUES (?, ?)",
        [(row["id"], row["document"]) for row in rows],
    )
    names = [name for name, _ in META_COLUMNS]
    placeholders = ", ".join("?" for _ in names)
    conn.executemany(
        f"INSERT OR REPLACE INTO {META_TABLE}({', '.join(names)}) "
        f"VALUES ({placeholders})",
        [
            tuple(
                row["id"] if name == "cve_id" else row["metadata"].get(name)
                for name in names
            )
            for row in rows
        ],
    )


def document_count(conn: sqlite3.Connection) -> int:
    """Number of documents in the FTS index."""
    return conn.execute(f"SELECT count(*) FROM {FTS_TABLE}").fetchone()[0]


def _where_clause(filters: Optional[Dict[str, Any]]) -> Tuple[str, List[Any]]:
    """
    Translate a filter dict into a SQL predicate over the metadata table.

    Supported keys mirror what an analyst actually narrows by:
      severity        exact match, or a list of severities
      min_cvss        cvss_base_score >= value
      max_cvss        cvss_base_score <= value
      published_after / published_before   epoch seconds
      vendor / product / cwe               substring match on the packed lists
      year            exact match, or a list of years
    """
    if not filters:
        return "", []

    clauses: List[str] = []
    params: List[Any] = []

    def add_in(column: str, value: Any) -> None:
        if isinstance(value, (list, tuple, set)):
            values = list(value)
            if not values:
                # An empty allow-list matches nothing; say so explicitly rather
                # than silently dropping the filter.
                clauses.append("0")
                return
            clauses.append(f"m.{column} IN ({', '.join('?' for _ in values)})")
            params.extend(values)
        else:
            clauses.append(f"m.{column} = ?")
            params.append(value)

    if "severity" in filters:
        add_in("severity", filters["severity"])
    if "year" in filters:
        add_in("year", filters["year"])
    if "min_cvss" in filters:
        clauses.append("m.cvss_base_score IS NOT NULL AND m.cvss_base_score >= ?")
        params.append(filters["min_cvss"])
    if "max_cvss" in filters:
        clauses.append("m.cvss_base_score IS NOT NULL AND m.cvss_base_score <= ?")
        params.append(filters["max_cvss"])
    if "published_after" in filters:
        clauses.append("m.published_ts IS NOT NULL AND m.published_ts >= ?")
        params.append(filters["published_after"])
    if "published_before" in filters:
        clauses.append("m.published_ts IS NOT NULL AND m.published_ts <= ?")
        params.append(filters["published_before"])
    # Packed delimited lists: match a whole element, not an arbitrary substring,
    # so "log4j" cannot match "log4j-extras" and "ssl" cannot match "openssl".
    for key, column in (("vendor", "vendors"), ("product", "products"), ("cwe", "cwe_ids")):
        if key in filters:
            clauses.append(
                f"('|' || lower(coalesce(m.{column}, '')) || '|') LIKE ?"
            )
            params.append(f"%|{str(filters[key]).lower()}|%")

    return (" AND ".join(clauses), params)


def search(
    conn: sqlite3.Connection,
    query: str,
    limit: int,
    filters: Optional[Dict[str, Any]] = None,
) -> List[Tuple[str, float]]:
    """
    BM25 search, optionally restricted to records matching `filters`.

    Returns (cve_id, score) best-first, with score negated so larger is better.
    Filtering is a join predicate rather than a post-filter, so `limit` returns
    that many *matching* records instead of however many survive trimming.
    """
    match_expr = escape_fts_query(query)
    if not match_expr:
        return []

    where, params = _where_clause(filters)
    sql = (
        f"SELECT f.cve_id AS cve_id, bm25({FTS_TABLE}) AS score "
        f"FROM {FTS_TABLE} f "
    )
    if where:
        sql += f"JOIN {META_TABLE} m ON m.cve_id = f.cve_id "
    sql += f"WHERE {FTS_TABLE} MATCH ? "
    if where:
        sql += f"AND ({where}) "
    sql += "ORDER BY score LIMIT ?"

    try:
        rows = conn.execute(sql, [match_expr, *params, limit]).fetchall()
    except sqlite3.OperationalError as exc:
        # Should be unreachable because the query is fully escaped, but a
        # malformed MATCH must not take down the caller.
        raise LexicalIndexError(f"FTS query failed for {query!r}: {exc}") from exc

    # bm25() is negative-better; negate so callers can treat larger as better.
    return [(row["cve_id"], -float(row["score"])) for row in rows]


def get_by_id(conn: sqlite3.Connection, cve_id: str) -> Optional[Dict[str, Any]]:
    """Fetch one record's metadata by exact CVE ID, or None."""
    row = conn.execute(
        f"SELECT * FROM {META_TABLE} WHERE cve_id = ?", (cve_id,)
    ).fetchone()
    return dict(row) if row else None


def filter_ids(
    conn: sqlite3.Connection, filters: Dict[str, Any], limit: Optional[int] = None
) -> List[str]:
    """Return CVE IDs matching a metadata filter, ignoring relevance entirely."""
    where, params = _where_clause(filters)
    sql = f"SELECT cve_id FROM {META_TABLE} m"
    if where:
        sql += f" WHERE {where}"
    if limit is not None:
        sql += " LIMIT ?"
        params = [*params, limit]
    return [row["cve_id"] for row in conn.execute(sql, params).fetchall()]

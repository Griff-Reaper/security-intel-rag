# Security Intelligence RAG System

> AI-powered security intelligence platform using Retrieval Augmented Generation (RAG) with Claude API and vector search

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Anthropic Claude](https://img.shields.io/badge/Claude-Opus%205-orange.svg)](https://www.anthropic.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Project status.** The corpus is the full NVD CVE dataset — see
> [Corpus](#-corpus) for exact counts, source and pull date, all recorded in the
> committed [provenance manifest](data/manifest.json). Retrieval is hybrid:
> dense vectors fused with BM25 by reciprocal rank fusion, then reranked by a
> cross-encoder, with metadata pre-filtering and direct CVE-ID routing. Every accuracy and latency figure
> below comes from a committed result file produced by a script in
> [experiments/](experiments/) — see [Measured behaviour](#-measured-behaviour).
> Retrieval is evaluated twice: once with queries drawn from the indexed
> documents themselves, which flatters lexical matching, and once against a
> committed set of 192 paraphrased analyst-style questions built to remove that
> advantage. Exploitation signals from CISA KEV and FIRST EPSS are joined in as
> filterable metadata. **End-to-end answer quality — groundedness and refusal
> behaviour — is still unmeasured**; see [Roadmap](#-roadmap).

## 🎯 Problem Statement

Security teams are overwhelmed with vulnerability data, threat intelligence feeds, and security advisories. Finding relevant information quickly and getting actionable intelligence requires:
- Manual searching across multiple sources
- Deep expertise to correlate threats
- Time-consuming analysis of CVEs and threat reports

**This system solves that** by providing AI-powered semantic search and intelligent analysis of security data.

## 💡 Solution

A Retrieval Augmented Generation (RAG) system that:
1. **Ingests** CVE databases and threat intelligence feeds into a vector database
2. **Retrieves** relevant security documents based on semantic similarity
3. **Generates** informed answers using Claude AI with retrieved context
4. **Exposes** REST API for integration with security tools

### Key Features

- 🔍 **Hybrid Search**: Dense vectors for meaning, BM25 for exact identifiers,
  fused by reciprocal rank fusion and reranked by a cross-encoder
- 🎯 **Direct CVE-ID Routing**: A query containing a CVE identifier is answered
  by a keyed lookup rather than a ranking, because ranked retrieval measurably
  fails on exactly the best-known CVEs
- 🤖 **AI-Powered Analysis**: Claude provides expert security analysis
- 📊 **Source Citations**: Answers carry the CVE IDs of the retrieved documents,
  taken from stored metadata rather than from generated text
- 🎯 **Metadata Pre-filtering**: Narrow by severity, CVSS range, publication
  date, vendor, product or CWE *before* ranking, so asking for 5 results returns
  5 matching ones rather than however many of the top 5 happened to match
- 🔥 **Exploitation Signals**: CISA KEV and FIRST EPSS joined by CVE ID, so
  results can be prioritised by observed exploitation rather than CVSS alone —
  590 of 36,797 CVSS-critical CVEs are actually known-exploited
- 🚀 **REST API**: Easy integration with SIEM, SOAR, and custom tools
- 💰 **Cost-Effective**: Local embeddings and lexical index (free) + Claude API
  (pay-per-use)

Every retrieval claim above is measured in
[Measured behaviour](#-measured-behaviour), including the configurations that
came out *worse*.

## 🏗️ Architecture

**Ingestion** (offline, run once then refreshed incrementally):

```text
fkie-cad bulk feeds          NVD API 2.0
(CVE-<year>.json.xz)         (lastMod window)
      │  sha256-verified           │  only changed records
      └──────────────┬─────────────┘
                     ▼
        nvd_normalize.py  ──  one document per CVE
                     │        embedded: ID, severity, vendor/product, CWE, description
                     │        metadata: CVSS score+vector, dates, CWE, CPE counts
                     ▼
        ingest_nvd.py  ──  batched embeddings, resumable checkpoint
                     │
                     ├──▶ ChromaDB (cosine)        dense arm
                     └──▶ build_fts.py ──▶ SQLite FTS5   lexical arm
                                    │
                     data/manifest.json records both
```

Both indexes are built from the *same* normalized records through the same
`nvd_normalize` functions, and `build_fts.py` verifies that afterwards: document
counts must match and a random sample of documents must be byte-identical on
both sides. Fusing two indexes that hold different text would rank documents
against each other that are not the same documents.

**Query** (online):

```text
                    "log4j 2.14.1"   +   optional filter
                                          severity / CVSS / date / vendor / CWE
                                          KEV / EPSS
                             │
                             ├──▶ contains CVE-\d{4}-\d{4,} ?
                             │    keyed lookup, prepended at rank 1
                             │    (0.03 ms; still subject to the filter)
                             │
             ┌───────────────┴───────────────┐
             ▼                               ▼
   ChromaDB (cosine)                 SQLite FTS5 (BM25)
   384-dim, top 200                  top 200
   understands meaning,              matches identifiers exactly,
   blind to identifiers              blind to synonyms
             │                               │
             └───────────────┬───────────────┘
                             ▼
              Reciprocal Rank Fusion (k = 60)
              broadens the candidate pool
                             │
                             ▼
              Cross-encoder rerank of the top 50
              converts that pool into precision
                             │
                             ▼
              Context formatter ──▶ Claude ──▶ answer + metadata citations
```

The filter is applied *inside* both arms, not after fusion. A post-filter would
return however many of the top 200 happened to match; a pre-filter returns 200
matching candidates.

## 📊 Corpus

Every figure below comes from [data/manifest.json](data/manifest.json), which is
written by the ingestion run itself — not typed by hand.

| | |
|---|---|
| **Source** | [fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds) — community reconstruction of the retired NVD JSON feeds, repackaged daily |
| **Upstream** | National Vulnerability Database (NVD), NIST |
| **Release** | `v2026.08.12-000016`, published 2026-08-12 |
| **Pulled** | 2026-08-12 |
| **Years** | 1999–2026 (28 per-year archives, sha256-verified) |
| **Raw records** | 376,092 |
| **Indexed** | 358,170 |
| **Filtered out** | 17,922 |
| **Licence** | NVD and CVE Terms of Use |

**What gets filtered.** 17,922 records are excluded because `vulnStatus` is
`Rejected` — the CVE was withdrawn by its assigner, and surfacing it would
present a vulnerability that does not exist. A second filter drops records with
no English description (nothing meaningful to embed); it matched nothing in this
pull, but incremental updates can introduce such records. Refreshes also
*delete* previously-indexed CVEs that have since been rejected.

### Document design

Each CVE becomes one document. The split between embedded text and stored
metadata is deliberate:

- **Embedded** (what retrieval matches against): the description, prefixed with
  the CVE ID, followed by affected vendors and products from CPE, CWE
  identifiers, and severity. Prose serves "remote code execution in Java logging
  libraries"; the product strings serve "log4j 2.14.1".
- **Stored, not embedded** (what filtering uses): CVSS base score, vector and
  version, severity, published/modified dates (kept as both ISO text and epoch
  integers so range queries work), CWE IDs, vendors, products, and CPE counts.
  Embedding a CVSS vector string would add noise to the vector without helping
  retrieval.

Two ordering decisions were made by measurement rather than taste, and both are
reproducible via [experiments/document_layout.py](experiments/document_layout.py):

**Vendor and product names are ordered CNA-first.** The `affected` block comes
from the party that reported the vulnerability, so it names the software that is
actually broken; the CPE tree instead enumerates every downstream product that
bundles it. Log4Shell makes the difference concrete — its CNA entry is *Apache
Log4j2*, while its 396 CPE entries begin with Siemens firmware part numbers. On
CPE ordering, `log4j` landed 11th and would be truncated out entirely on a
record with more vendors.

**The description leads, and product lists are capped at 6 vendors / 8
products.** Putting metadata first measurably dilutes the description's
contribution to the vector, and the damage scales with how many products a CVE
lists:

| Affected products | n | metadata-first | description-first | Δ recall@1 |
|---|---:|---:|---:|---:|
| 1–5 | 1,013 | 0.960 | 0.963 | +0.004 |
| 6–20 | 138 | 0.746 | 0.790 | +0.043 |
| 21–60 | 26 | 0.769 | 0.962 | **+0.192** |
| 61+ | 19 | 0.947 | 1.000 | +0.053 |

Description-first was never worse in any bucket. **These numbers are not a
retrieval evaluation** — the queries are the documents' own opening sentences,
so they share vocabulary with the target and every absolute figure is inflated.
Only the comparison between layouts is meaningful, and the 21–60 bucket rests on
26 samples, so treat that delta's magnitude as indicative rather than precise.
A real evaluation, with paraphrased questions and a committed eval set, is
[still to come](#-roadmap).

## 🔥 Exploitation signals

CVSS says how bad a vulnerability would be if exploited. It says nothing about
whether anyone is exploiting it — and that difference is most of the triage
problem:

| | Count | Share of corpus |
|---|---:|---:|
| CVSS base score ≥ 9.0 | 47,057 | 13.1% |
| Severity CRITICAL | 36,797 | 10.3% |
| **CRITICAL *and* known exploited** | **590** | **0.16%** |
| In CISA KEV at all | 1,665 | 0.46% |
| KEV, linked to ransomware campaigns | 339 | 0.09% |
| EPSS ≥ 0.5 | 4,311 | 1.2% |

Ranking by CVSS alone puts 36,797 "critical" findings in front of an analyst
with nothing to separate the 590 under active exploitation from the rest.

Two feeds, joined by CVE ID, because they answer different questions:

- **[CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)** —
  vulnerabilities with *confirmed, observed* exploitation. Ground truth, small,
  and carries a federal remediation due date plus a ransomware-campaign flag.
- **[FIRST EPSS](https://www.first.org/epss/)** — a model's estimated
  probability of exploitation in the next 30 days. A prediction rather than an
  observation, but it covers essentially the whole corpus.

```bash
python src/exploitation.py       # inspect both feeds
python src/enrich_index.py       # join them onto the index
python src/enrich_index.py --check   # coverage, without writing
```

Coverage from the run recorded in [data/manifest.json](data/manifest.json):
**358,167 of 358,170 documents carry an EPSS score**; 3 do not appear in the
EPSS feed at all, and 481 feed entries name CVEs this corpus does not hold.

### Two decisions worth stating

**Enrichment is metadata only. Nothing is re-embedded.** EPSS re-scores the
whole corpus daily and KEV grows weekly; embedding either into the document text
would mean an hour of re-embedding to capture a number that changes again
tomorrow. It also keeps the document layout fingerprint unchanged, so every
result file committed under Phase 2 still describes the index that ships — the
drift protection below doing its job.

The honest cost: a question like *"what is being actively exploited right now"*
will not semantically match KEV membership, because KEV membership is not in the
embedded text. Exploitation is a **filter** here, not a retrieval signal. Making
it one is query understanding — mapping such a question onto a filter — and is
not built.

**`NULL` is not `False`.** A CVE that was never checked against KEV and a CVE
that was checked and is not listed are different facts. `kev: false` matches only
the second. Collapsing them would report an unknown as an all-clear, which is
the wrong direction to be wrong in for a security tool. Tests pin it.

One more thing the two EPSS numbers invite getting wrong: `CVE-1999-0001` scores
**0.034** — which reads as negligible — and sits at the **88th percentile**,
because most CVEs score lower still. `min_epss` asks "how likely is this to be
attacked"; `min_epss_percentile` asks "how does this compare to everything
else". Both are stored so a caller can pick the question they mean.

### Which index does a result describe?

The pinned sample stops the *queries* drifting between measurements. Nothing
stopped the *documents* drifting: change the layout above, re-ingest, and every
committed result file silently starts describing a corpus rendering that no
longer exists.

[src/nvd_normalize.py](src/nvd_normalize.py) therefore carries a
`layout_fingerprint()` — a hash of the documents the module renders for a set of
fixed synthetic fixtures. Not a hash of its source, which would trip on every
comment edit, and not a hand-maintained version number, which relies on
remembering to bump it. The fixtures exercise each layout decision (field order,
both text caps, both metadata caps, CNA-before-CPE vendor ordering, the list
delimiter, CVSS precedence), so the hash moves when and only when the rendered
documents move. Tests assert both directions.

That fingerprint is recorded in [data/manifest.json](data/manifest.json) at
ingest time and stamped into every result file alongside `generated_at`. Every
experiment calls `require_layout_match()` first and **refuses to run** if the
live layout differs from the one the index was built with, rather than producing
numbers that look valid and describe something else.

For the currently shipped index the question is settled by evidence rather than
bookkeeping, because the manifest predates this mechanism.
`python src/provenance.py --record` re-normalizes raw feed records from 2014,
2021 and 2025 with the current code and compares them against what ChromaDB
actually stores: **1,500 documents compared, 0 mismatches**. The ablation
therefore describes the index that ships.

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **LLM** | Claude Opus 5 (Anthropic) | Intelligent analysis and generation |
| **Embeddings** | Sentence Transformers (all-MiniLM-L6-v2) | Free, fast semantic embeddings (384-dim) |
| **Vector Database** | ChromaDB | Local persistent vector storage — dense arm |
| **Lexical Index** | SQLite FTS5 | On-disk BM25 over an inverted index — lexical arm |
| **Reranker** | cross-encoder/ms-marco-MiniLM-L-6-v2 | Re-scores the fused top 50 |
| **API Framework** | FastAPI | Modern async Python web framework |
| **Exploitation** | CISA KEV + FIRST EPSS | Observed and predicted exploitation |
| **Testing** | Pytest | 302 unit tests |

SQLite FTS5 rather than a pip BM25 package: `rank_bm25` and similar hold the
whole index in memory and score every document on every query. At 358,170
documents that is slow and memory-hungry. FTS5 ships with the standard library,
stores its index on disk, and touches only the postings for terms the query
actually contains.

## 📦 Installation

### Prerequisites

- Python 3.11 or higher
- Anthropic API key ([get one here](https://console.anthropic.com/))
- Enough disk space for the Python environment, the embedding model (downloaded
  on first run), and the local vector store

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/Griff-Reaper/security-intel-rag.git
cd security-intel-rag
```

2. **Create virtual environment**
```bash
python -m venv venv

# Activate it:
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

5. **Download the corpus**
```bash
python src/nvd_feeds.py --dest data/raw
```

Downloads one compressed archive per CVE year and verifies each against the
sha256 in its `.meta` sidecar. Already-verified files are reused, so re-running
is cheap and an interrupted download is safe to repeat.

6. **Ingest**
```bash
python src/ingest_nvd.py
```

Normalizes, embeds and indexes every CVE into a local ChromaDB store under
`chroma_db/`. The first run also downloads the embedding model. See
[Corpus](#-corpus) for measured throughput and runtime.

Ingestion is **resumable**: progress is checkpointed after every committed
batch, so a run interrupted at 80% continues from where it stopped rather than
starting over. It is also idempotent — records are upserted, so re-running never
duplicates. To rebuild from scratch, pass `--reset`.

Optional flags:

```bash
python src/ingest_nvd.py --years 2024 2025   # a subset, for a quick trial
python src/ingest_nvd.py --reset             # drop the collection and rebuild
```

7. **Build the lexical index**

```bash
python src/build_fts.py
```

Builds the SQLite FTS5 index that the BM25 arm searches — about **1.1 minutes**
for the full corpus. It reads the same feed files through the same normalization
functions as the ingest above, then verifies itself against ChromaDB: counts
must match and a random sample of documents must be byte-identical. Required for
every retrieval mode except `dense`; `src/query.py` refuses to start without it
rather than silently downgrading.

```bash
python src/build_fts.py --verify-only   # re-check an existing index
```

**Keeping the corpus current**

```bash
python src/nvd_api.py --days 7                  # preview what changed
python src/ingest_nvd.py --refresh --days 7     # apply those changes
```

Refreshes use the NVD API 2.0 `lastModStartDate` / `lastModEndDate` window, so
they pull only records that actually changed — a few hundred a day rather than
the whole corpus. Changed records are upserted; records that have since been
**Rejected are deleted** from the index, because a CVE can be withdrawn after
publication and a stale copy would keep presenting it as a real vulnerability.

NVD allows 5 requests per 30 seconds anonymously and 50 with a free
[API key](https://nvd.nist.gov/developers/request-an-api-key); set `NVD_API_KEY`
in `.env` to get the higher limit. The key is read from the environment and
never stored in the repository.

## 🚀 Usage

### Command Line Interface

Interactive query interface:

```bash
python src/query.py
```

Example session. The source list is real output from the live index; the answer
body is elided because it comes from a metered API call and is not reproducible
verbatim:

```text
Your question: What vulnerabilities affect Citrix NetScaler?

ANSWER:
[Claude's analysis, grounded in the retrieved documents]

SOURCES (3 documents used):
1. [CVE] CVE-2018-6811
   Severity: MEDIUM (CVSS 6.1)
   Products: netscaler application delivery controller firmware, netscaler
   Rank: 1
2. [CVE] CVE-2021-22919
   Severity: HIGH (CVSS 7.5)
   Products: Citrix ADC, Citrix Gateway, Citrix SD-WAN WANOP
   Rank: 2
3. [CVE] CVE-2021-22920
   Severity: MEDIUM (CVSS 6.5)
   Products: Citrix ADC, Citrix Gateway
   Rank: 3
```

Retrieval is usable without an Anthropic key via `retrieve_context()` — see the
Python example below. Only answer generation calls the API.

### REST API

Start the API server:

```bash
python src/api.py
```

The API will be available at:
- **Main API**: http://localhost:8000
- **Interactive Docs**: http://localhost:8000/docs (Swagger UI)
- **API Documentation**: http://localhost:8000/redoc

#### API Examples

**Basic Query:**
```bash
curl -X POST "http://localhost:8000/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What are the critical VMware vulnerabilities?",
    "n_results": 5
  }'
```

**Filtered Query (pre-filtered before ranking):**
```bash
curl -X POST "http://localhost:8000/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What mitigations exist for authentication bypass?",
    "severity": ["CRITICAL", "HIGH"],
    "vendor": "apache",
    "min_cvss": 9.0,
    "query_type": "mitigation"
  }'
```

Supported filters: `severity`, `vendor`, `product`, `cwe`, `min_cvss`,
`max_cvss`, `published_after`, `published_before`. An unrecognised filter field
is a `422`, never a silently unfiltered answer.

**Health Check:**
```bash
curl http://localhost:8000/health
```

### Python SDK Usage

Use the RAG system programmatically:

```python
from src.query import SecurityRAG

# Defaults to hybrid_rerank + direct-ID routing, the configuration the ablation
# measured best. Pass retrieval="dense"/"bm25" or direct_id=False to compare.
rag = SecurityRAG()

# Routed: fetched by key, not ranked. Returns the Log4Shell record first,
# which no ranked configuration does.
result = rag.query("What mitigates CVE-2021-44228?")

# Simple query
result = rag.query("What are the latest ransomware threats?")
print(result["answer"])

# Pre-filtered query
result = rag.query_with_filters(
    question="Tell me about critical Exchange vulnerabilities",
    severity=["CRITICAL", "HIGH"],
    vendor="microsoft",
    min_cvss=9.0,
)

# Retrieval only, no Claude call and no API key needed
hits = rag.retrieve_context("log4j 2.14.1", n_results=5,
                            filters={"vendor": "apache"})
for meta, rank in zip(hits["metadatas"], hits["ranks"]):
    print(rank, meta["cve_id"], meta["severity"])
```

Citations carry a **rank**, not a similarity score. Each backend scores on its
own scale — cosine distance, BM25, an RRF sum, a cross-encoder logit — so a
single `distance` field would mean something different per configuration while
looking comparable.

## 📊 Project Structure

```text
security-intel-rag/
├── README.md                    # This file
├── LICENSE                      # MIT license
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore rules
│
├── src/                         # Source code
│   ├── embeddings.py            # Embedding generation service
│   ├── nvd_feeds.py             # Bulk corpus download + sha256 verification
│   ├── nvd_api.py               # NVD API 2.0 incremental updates
│   ├── nvd_normalize.py         # CVE record -> document + metadata
│   ├── ingest_nvd.py            # Resumable corpus ingestion (main pipeline)
│   ├── exploitation.py          # CISA KEV + FIRST EPSS fetch and parse
│   ├── enrich_index.py          # Joins exploitation signals onto the index
│   ├── provenance.py            # Document-layout fingerprint and drift check
│   ├── significance.py          # Paired McNemar tests for retrieval comparisons
│   ├── claude_client.py         # Guarded Anthropic client (SDK version assert)
│   ├── ingest.py                # Legacy sample-data loader (demo only)
│   ├── lexical_index.py         # SQLite FTS5 BM25 index + query escaping
│   ├── build_fts.py             # Builds the lexical index, verifies vs Chroma
│   ├── retrieval.py             # dense | bm25 | hybrid | hybrid_rerank
│   ├── filters.py               # Metadata pre-filter spec, both backends
│   ├── query.py                 # RAG query engine
│   └── api.py                   # FastAPI REST service
│
├── config/                      # Configuration
│   └── prompts.py               # Claude system prompts
│
├── data/
│   ├── manifest.json            # Provenance: source, pull date, counts
│   ├── sample_cves.json         # Legacy demo data (not the corpus)
│   ├── threat_intel.json        # Legacy demo data (not the corpus)
│   └── raw/                     # Downloaded feeds (generated, gitignored)
│
├── experiments/                 # Re-runnable measurements behind design claims
│   ├── document_layout.py       # Chooses the embedded-document layout
│   ├── identifier_queries.py    # The ablation, --retrieval x --direct-id
│   ├── fts_tokenizer.py         # Chooses the FTS5 tokenizer
│   ├── rrf_ties.py              # Chooses the RRF tie-break (dev sample)
│   ├── lexical_latency.py       # Locates the BM25 latency tail
│   ├── crossref_identifiers.py  # Splits ID lookup by cross-reference
│   ├── build_eval_set.py        # Generates the paraphrased eval set
│   ├── paraphrased_queries.py   # The paraphrased ablation + paired tests
│   ├── samples/                 # Pinned evaluation and dev samples
│   └── results/                 # Committed JSON output of the above
│
├── tests/                       # 302 unit tests
│   ├── test_rag.py              # Embedding + formatting tests
│   ├── test_nvd_normalize.py    # Normalization, CVSS, CPE, filtering
│   ├── test_nvd_sources.py      # Feed verification + API windowing
│   ├── test_lexical_index.py    # FTS5 query escaping, ranking, filtering
│   ├── test_retrieval.py        # RRF arithmetic, tie-breaks, rerank ordering
│   └── test_filters.py          # Pre-filter invariant on both backends
│
└── chroma_db/                   # Vector + lexical indexes (generated, gitignored)
```

Neither index is committed. A collection of this size cannot be meaningfully
reviewed in a repository, so the build scripts plus
[data/manifest.json](data/manifest.json) are the committed artifacts — they let
anyone rebuild the exact corpus and check the numbers. The pinned evaluation
sample and every result file *are* committed, so the ablation can be
re-derived rather than taken on trust.

## 🧪 Testing

Run tests:

```bash
pytest tests/ -v
```

Run specific test:

```bash
pytest tests/test_rag.py::TestEmbeddings -v
```

## 💰 Cost Profile

| Component | Cost | Notes |
|-----------|------|-------|
| **Embeddings** | Free | Sentence Transformers runs locally on CPU |
| **Vector Database** | Free | ChromaDB is open-source and runs locally |
| **Lexical Index** | Free | SQLite FTS5, part of the standard library |
| **Reranker** | Free | Cross-encoder runs locally on CPU |
| **Claude API** | Metered | Billed per token — see [current pricing](https://platform.claude.com/docs/en/pricing) |

Only the Claude API call costs money; the whole retrieval stack — embedding,
vector search, BM25, and reranking — is local. Retrieval latency is measured
(see [Measured behaviour](#-measured-behaviour)); **per-query token cost is
not**, and no figure is quoted here until it comes from a committed,
re-runnable benchmark.

## 📈 Measured behaviour

Ingestion throughput, from [data/manifest.json](data/manifest.json): **358,170
documents in 59.9 minutes — 100 documents/second** embedding and indexing on
CPU, single process. The lexical index adds **1.1 minutes at 5,434
documents/second**.

Every number in this section is read from a committed file in
[experiments/results/](experiments/results/), written by a script in
[experiments/](experiments/) that can be re-run. The evaluation sample is pinned
to [experiments/samples/identifier_sample.json](experiments/samples/identifier_sample.json)
and committed, so all four configurations answer byte-identical queries. Where a
parameter had to be chosen, it was chosen on a separate dev sample that shares
no CVEs with the evaluation sample.

### The retrieval ablation

[experiments/identifier_queries.py](experiments/identifier_queries.py) against
the live 358,170-document index, 200 pinned CVEs, three query shapes.

**Product + version** — the realistic query, and the one worth reading first:

| Retrieval | Recall@1 | Recall@10 | Found in top 100 | MRR | p50 | p95 |
|---|---:|---:|---:|---:|---:|---:|
| dense | 0.122 | 0.270 | 0.434 | 0.173 | 20 ms | 23 ms |
| bm25 | 0.235 | 0.515 | 0.745 | 0.324 | 15 ms | 588 ms |
| hybrid (RRF) | 0.204 | 0.474 | 0.775 | 0.299 | 73 ms | 700 ms |
| **hybrid + rerank** | **0.306** | **0.633** | 0.775 | **0.416** | 584 ms | 1347 ms |

**Bare CVE ID** (`CVE-2021-44228`) — read with the caveat below it:

| Retrieval | Recall@1 | Recall@10 | Found in top 100 | MRR |
|---|---:|---:|---:|---:|
| dense | 0.000 | 0.000 | 0.005 | 0.000 |
| bm25 | **0.995** | 1.000 | 1.000 | 0.998 |
| hybrid (RRF) | 0.995 | 1.000 | 1.000 | 0.997 |
| hybrid + rerank | 0.965 | 0.995 | 1.000 | 0.977 |

**Query routing, not retrieval.** Direct CVE-ID routing is reported separately
because it does not improve a ranking — it recognises that the question has an
exact answer and fetches it by key, so the ranker is never asked. It is
orthogonal to the retrieval mode (`--direct-id` composes with any `--retrieval`):

| Configuration | Bare CVE ID | Product + version | Control |
|---|---:|---:|---:|
| dense | 0.000 | 0.122 | 0.765 |
| dense **+ direct ID** | **1.000** | 0.122 *(unchanged)* | 0.760 |
| hybrid + rerank | 0.965 | 0.306 | 0.860 |
| hybrid + rerank **+ direct ID** | **1.000** | 0.306 *(unchanged)* | 0.855 |

Routing fired on 202 of 596 queries (33.9%) and costs **0.03 ms at p50**
(regex plus a primary-key lookup, measured interleaved in
[experiments/lexical_latency.py](experiments/lexical_latency.py)). It leaves
product + version untouched, because those queries contain no identifier to
route.

It is not free of cost, and the cost shows up where you would not look for it:
the control row drops 0.005. Two of the 200 description sentences quote a
*different* CVE's identifier, and routing correctly promotes that record — which
pushes the intended target down. One query lost rank 1 that way. That is the
honest shape of a routing rule: it answers the question the text actually asks,
which is not always the question the benchmark meant.

**Description sentence** *(control — see the caveat, this row is not an
evaluation)*:

| Retrieval | Recall@1 | Recall@10 | Found in top 100 | MRR |
|---|---:|---:|---:|---:|
| dense | 0.765 | 0.860 | 0.895 | 0.803 |
| bm25 | 0.870 | 0.970 | 1.000 | 0.909 |
| hybrid (RRF) | 0.855 | 0.955 | 0.995 | 0.894 |
| hybrid + rerank | 0.860 | 0.970 | 0.995 | 0.902 |

### What the ablation actually shows

**Fusion buys recall depth; reranking converts it to precision; neither works
alone.** On product + version, fusion *lowers* Recall@1 from BM25's 0.235 to
0.204 — it dilutes a strong lexical signal with a weak dense one. But it raises
found-in-top-100 from 0.745 to 0.775, because the two arms fail on different
documents. The cross-encoder then turns that wider pool into 0.306 at rank 1,
the best of any configuration. Run either stage without the other and the gain
is not there. This is the opposite of the "hybrid is better, ship it" conclusion
that a project reaches by not checking.

**Reranking bought a lot here, and it is not cheap.** +0.071 Recall@1 over BM25
alone on product + version, for a p50 of 584 ms against 15 ms — roughly 40× the
latency for a 30% relative gain. The rerank step alone is 381 ms at p50
([results](experiments/results/identifier_queries_hybrid_rerank.json)). Whether
that trade is worth making depends on the deployment; in this system a
multi-second Claude call follows, so it is.

**Configurations that came out worse, stated rather than omitted:**

- `hybrid` is below `bm25` at Recall@1 on two of three query shapes (the gap is
  not statistically significant: 5 wins to 11, p = 0.21).
- `hybrid + rerank` is below `bm25` on bare CVE IDs (0.965 vs 0.995): the
  cross-encoder demotes six identifier matches it was handed at rank 1.
- Nothing beats `dense` on latency; it is the fastest configuration and the
  least accurate on every row.

### "BM25 solves CVE-ID lookup" is not true, and here is the number

Taken alone, BM25's 0.995 on bare identifiers looks like a solved problem. It is
an artifact of who is in the sample.
[experiments/crossref_identifiers.py](experiments/crossref_identifiers.py) scans
all 358,170 documents and splits the corpus by whether *another* CVE record
mentions the ID. **11,001 CVEs — 3.07% — are cross-referenced.**

| Population | dense | bm25 | hybrid | hybrid + rerank | **+ direct ID** |
|---|---:|---:|---:|---:|---:|
| Not cross-referenced (96.9%) | 0.000 | **1.000** | 1.000 | 0.967 | **1.000** |
| Cross-referenced (3.1%) | 0.000 | 0.673 | 0.673 | 0.967 | **1.000** |
| Widely-known, named not sampled | 0.000 | 0.667 | 0.667 | 0.667 | **1.000** |

BM25 is *perfect* on the 97% of CVEs that nothing cites and drops to 0.673 on the
3% that are cited — and a uniform random sample is almost entirely the former.
The cause is document-length normalization: a heavily-analysed CVE accumulates
vendors and products, so its record is the longest of the documents containing
its ID, and BM25 ranks the longest last. Searching `CVE-2021-44228` returned, in
order, four CVEs that merely *cite* Log4Shell before the Log4Shell record itself.

Reranking recovers most of it — 0.673 → 0.967 on the cross-referenced population,
because a cross-encoder can tell "the record about Log4Shell" from "a record
citing Log4Shell". It was still not enough for the best-known CVEs, which is what
made routing worth building:

| CVE | Docs citing it | dense | bm25 | hybrid | hybrid + rerank | **+ direct ID** |
|---|---:|---:|---:|---:|---:|---:|
| CVE-2021-44228 (Log4Shell) | 10 | miss | 5 | 9 | 7 | **1** |
| CVE-2014-0160 (Heartbleed) | 3 | miss | 3 | 5 | 2 | **1** |
| CVE-2014-6271 (Shellshock) | 4 | miss | 3 | 5 | 2 | **1** |
| CVE-2021-45046 (Log4j follow-up) | 3 | miss | 3 | 5 | 2 | **1** |
| CVE-2017-0144 (EternalBlue) | 5 | miss | 1 | 1 | 1 | 1 |
| CVE-2019-0708 (BlueKeep) | 1 | miss | 1 | 1 | 1 | 1 |

Before routing, **typing the most famous CVE identifier in the corpus did not
return its record first in any configuration** — Log4Shell sat at rank 5, 9 and
7. Ranked retrieval cannot fix this in general: BM25 is structurally biased
against the longest document containing a term, and the authoritative record is
usually the longest. A keyed lookup sidesteps the question. All 12 named CVEs
now return at rank 1.

This is why routing is worth its twenty lines despite BM25's 0.995: the average
was measuring a population that was never in doubt.

### Does dense retrieval earn its place? (paraphrased eval set)

The control row above is compromised by construction, so it could not answer the
question it appeared to answer. [experiments/build_eval_set.py](experiments/build_eval_set.py)
builds the missing test: for each CVE in the same pinned sample, a question
phrased the way an analyst would ask it, generated by Claude from the
description with instructions to paraphrase rather than quote. **192 of 200**
CVEs produced a usable question; the set is committed to
[experiments/samples/paraphrased_eval.json](experiments/samples/paraphrased_eval.json).

Same 200 CVEs as the identifier evaluation, different queries, so the two tables
describe one fixed set of documents.

| Retrieval | Recall@1 | Recall@10 | Found in top 100 | MRR | p50 |
|---|---:|---:|---:|---:|---:|
| dense | 0.479 | 0.688 | 0.771 | 0.559 | 34 ms |
| bm25 | 0.609 | 0.833 | 0.917 | 0.694 | 287 ms |
| hybrid (RRF) | 0.568 | 0.828 | 0.932 | 0.663 | 401 ms |
| **hybrid + rerank** | **0.625** | **0.854** | 0.932 | **0.711** | 996 ms |

**The answer is no — dense retrieval does not earn its place on this workload.**

Recall@1 differences on 192 questions are a few queries wide, so they are tested
as *paired* comparisons (McNemar exact, counting only the questions where the two
configurations disagree) rather than read off the averages:

| Comparison | A wins | B wins | p |
|---|---:|---:|---:|
| bm25 vs dense | 42 | 17 | **0.002** |
| hybrid + rerank vs dense | 38 | 10 | **<0.001** |
| hybrid + rerank vs bm25 | 26 | 23 | 0.775 |
| hybrid vs bm25 | 8 | 16 | 0.152 |

BM25 alone beats dense decisively. Adding the dense arm on top of BM25 produces
**no measurable gain at any depth** — Recall@1 p = 0.775, Recall@10 p = 0.424,
top-100 p = 0.375. The 1.6-point headline advantage of `hybrid + rerank` over
`bm25` is three queries out of 192.

The arm is not dead weight, though, and the paired data shows why: **dense
returns 17 questions at rank 1 that BM25 misses entirely**, and fusion keeps 14
of them. It also loses 42 the other way. So the dense arm is genuinely
complementary — it just is not complementary *enough* to pay for itself here.

**What would change this verdict**, stated so the result is not over-read:

- **Statistical power.** At n = 192 this design cannot reliably detect a true
  difference smaller than roughly 10 points. "No measurable gain" is not "no
  gain"; it is a bound on what this eval set can see.
- **A stronger embedding model.** `all-MiniLM-L6-v2` is 384-dimensional and
  three years old. The dense arm being outclassed by BM25 is partly a statement
  about this particular model, not about dense retrieval.
- **Query mix.** Every query here targets one specific CVE. Dense retrieval's
  natural advantage is on questions with no single right answer — "what should I
  patch first on my Citrix estate" — which this eval set contains none of.

### Why `hybrid + rerank` is still the default

Reading only the paraphrased table, the shipped default looks unjustifiable: it
costs 3.5× BM25's latency and an extra model dependency to buy a difference the
test cannot see. That reading is incomplete, because the two workloads disagree.
Running the same paired test per query shape
([experiments/results/identifier_paired_tests.json](experiments/results/identifier_paired_tests.json)
and [paraphrased_paired_tests.json](experiments/results/paraphrased_paired_tests.json)):

| Query shape | `hybrid+rerank` wins | `bm25` wins | p | Verdict |
|---|---:|---:|---:|---|
| **product + version** | **21** | **7** | **0.013** | hybrid+rerank better |
| product + version, @10 | 29 | 6 | **0.0001** | hybrid+rerank better |
| paraphrased question | 26 | 23 | 0.775 | no measurable difference |
| description control | 6 | 8 | 0.791 | no measurable difference |
| bare CVE ID | 1 | 7 | 0.070 | moot — routing puts both at 1.000 |

**`hybrid + rerank` is significantly better on one query shape and never
significantly worse on any of them.** Product + version — "log4j 2.14.1" — is
also the shape an analyst types most, and it is the row this project has treated
as the interesting one since Phase 2.

So the default stays, on the narrow grounds that it wins where it wins and does
not lose elsewhere — not on the grounds that it is more sophisticated. The cost
is real and the alternative is one environment variable away:

```bash
RETRIEVAL_MODE=bm25 python src/query.py
```

**Pick `bm25` if your queries are natural-language questions.** It is
statistically indistinguishable from `hybrid + rerank` on those, at roughly a
third of the latency and with no cross-encoder to download. **Keep the default
if product-and-version lookups are a meaningful share of your traffic.** Direct
CVE-ID routing is orthogonal and worth keeping either way — it costs 0.03 ms.

One caveat on the negative results above: with ~200 queries this design cannot
reliably detect a true difference below roughly ten points, so "no measurable
difference" bounds what the eval set can see rather than proving equivalence.

### How compromised is the paraphrasing?

Not fully clean, and the residue is measured rather than assumed. *Leakage* is
the share of a question's content words that also appear in its target document:

| Query set | Mean | Median |
|---|---:|---:|
| Copied-sentence control (Phase 2) | 0.988 | 1.000 |
| **Paraphrased question** | **0.475** | 0.462 |

Paraphrasing halves the overlap but cannot remove it — an analyst looking for a
Log4j bug types "log4j". Results are therefore also reported by leakage tercile,
and the low-leakage stratum is the closest thing here to a pure semantic test:

| Retrieval | Low leakage | Mid | High |
|---|---:|---:|---:|
| dense | 0.333 | 0.496 | 0.609 |
| bm25 | 0.417 | 0.632 | 0.783 |
| hybrid + rerank | 0.417 | 0.662 | 0.739 |

Every configuration degrades as leakage falls, which is the expected shape. Dense
retrieval is last in **every** stratum, including the one with the least
copying — so its poor showing is not an artifact of residual leakage favouring
the lexical arm.

### Three known defects in this eval set

1. **8 CVEs are missing, and not at random.** The generator's safety classifier
   declined to write search queries for certain vulnerability descriptions
   (privilege escalation, hypervisor denial of service). Those CVEs are listed
   with their reason in the committed `excluded` block rather than dropped
   silently, because their absence skews the set away from a particular kind of
   vulnerability.
2. **The questions are a model's idea of an analyst.** Real analyst queries would
   be shorter, more misspelled, and less complete. This is the weakest part of
   the methodology and no measurement here fixes it.
3. **15 of 192 descriptions are too vague to support a distinctive question**
   ("Unspecified vulnerability in ..."). They are kept and reported separately —
   every configuration scores ≤ 0.133 on them — because dropping them would
   inflate every headline number by removing exactly the hard records.

### A Phase 2 prediction, confirmed

Phase 2 predicted that the latency tail belongs to long queries and that "the
paraphrased natural-language questions of the planned eval set are long queries,
and they will sit in the tail." They do: BM25's p50 goes from **15 ms** on the
identifier query mix to **287 ms** here, and `hybrid + rerank` from 584 ms to
996 ms. The retrieval configuration that wins is also the one that costs a full
second per query.

### The control row is compromised by construction

The description-sentence queries are the documents' own opening sentences, so
they are drawn verbatim from the indexed text. That structurally favours lexical
matching, and it is why BM25 (0.870) outscores dense retrieval (0.765) on the
row labelled "semantic".

**On its own this row was not evidence that dense retrieval is useless** — the
query *was* the document, so the task rewarded string matching and told you
nothing about semantics. The paraphrased eval set above is the test that
settles it, and it reaches the same verdict for a better reason: BM25 beats
dense on paraphrased questions too (p = 0.002), in every leakage stratum, and
adding the dense arm on top of BM25 buys nothing measurable.

### Latency: where the tail comes from

BM25's p50 of 15 ms against a p95 of 588 ms is a 40× spread worth explaining
before quoting either figure.
[experiments/lexical_latency.py](experiments/lexical_latency.py) separates the
two candidate causes:

| Query shape | p50 | p95 |
|---|---:|---:|
| Bare CVE ID | 0.2 ms | 0.3 ms |
| Product + version | 7 ms | 64 ms |
| Description sentence | 460 ms | 635 ms |

The tail is **query length, not term commonality**. Holding the text fixed and
truncating it, cost rises from 16 ms at one term to 521 ms at 32; whereas the
single most common term in the corpus — `vulnerability`, in 168,571 of 358,170
documents — costs 71 ms on its own. No single term can produce the tail; only a
long query can, because terms are combined with `OR` and each one is another
postings list to walk. `MAX_QUERY_TERMS = 32` in
[src/lexical_index.py](src/lexical_index.py) is the cap that bounds it.

This matters for what comes next: the two shapes a person actually types are the
fast ones, but the paraphrased natural-language questions of the planned eval set
are long queries, and they will sit in the tail.

**A caveat on every latency figure here.** These are single-run measurements on a
developer machine, and the whole distribution moves between runs — in one pair of
`hybrid_rerank` runs minutes apart, every component was roughly twice as slow,
including components that the change under test could not touch. Comparisons
between two numbers measured in *separate* runs are therefore not reliable to
better than about 2×. Where a latency comparison had to be trustworthy — the
cost of direct-ID routing — it was measured interleaved in a single process
instead.

### Two parameters chosen by measurement

**Tokenizer.** [experiments/fts_tokenizer.py](experiments/fts_tokenizer.py) built
a 61,030-document subset under each candidate. Accuracy was *identical* (Recall@1
0.997 / 0.237); latency was 3.2 ms versus 15.4 ms. Keeping `-` and `.` as word
characters makes `CVE-2021-44228` a single token lookup instead of a multi-token
phrase match.

**RRF tie-breaking.** With two arms and k = 60, a document ranked *r* by one arm
alone scores 1/(60+r) — so when the arms return disjoint candidates, every rank
produces a two-way tie and the tie-break, not the formula, decides the ranking.
On bare CVE IDs that is 100% of targets.
[experiments/rrf_ties.py](experiments/rrf_ties.py), run on the dev sample:

| Tie-break | bare ID Recall@1 | product + version |
|---|---:|---:|
| Document ID (arbitrary) | 0.720 | 0.121 |
| **Prefer the lexical arm** | **0.985** (ceiling) | **0.126** (ceiling) |
| Prefer the dense arm | 0.000 | 0.095 |

Breaking ties on document ID is not the neutral choice — it is a coin flip that
discarded a quarter of the lexical arm's accuracy. The shipped tie-break prefers
the lexical arm and is labelled in the source as the arm weighting it is.

### Still not measured

End-to-end answer quality, groundedness, refusal behaviour on unanswerable
questions, and cost per query. Those need the paraphrased eval set; no figures
are quoted here until they come from a committed, re-runnable benchmark.

## 🔮 Roadmap

Planned, in order:

- [x] **Real corpus** — the full NVD dataset via bulk feeds, with a committed
      provenance manifest (source, pull date, record counts) and resumable,
      batched ingestion
- [x] **Hybrid retrieval** — dense + BM25 with reciprocal rank fusion,
      metadata pre-filtering, and cross-encoder reranking, each selectable so
      its contribution stays separately measurable
- [x] **Retrieval evaluation** — Recall@k and MRR on a pinned sample, a
      four-configuration ablation with p50/p95 latency, and parameters tuned on
      a disjoint dev sample
- [x] **Direct CVE-ID routing** — match `CVE-\d{4}-\d{4,}` and look the record up
      by key. Deferred once on the grounds that BM25 already reached 0.995 on
      identifiers; the [cross-reference
      split](#bm25-solves-cve-id-lookup-is-not-true-and-here-is-the-number)
      showed that average was hiding 0.667 on the best-known CVEs, which
      un-deferred it. Bare-ID Recall@1 is now 1.000 for 0.03 ms per query.
- [x] **Exploitation enrichment** — CISA KEV and FIRST EPSS joined by CVE ID,
      as filterable metadata rather than embedded text so a daily refresh costs
      minutes instead of an hour of re-embedding
- [x] **Paraphrased eval set** — 192 generated analyst-style questions over the
      same pinned CVEs, with leakage measured against the copied-sentence
      control and paired significance tests. Verdict: the dense arm does not
      earn its place on this workload
- [ ] **Answer-quality evaluation** — groundedness judging and refusal rate on
      unanswerable questions. The paraphrased set is the foundation for both;
      neither is built, and no answer-quality number is quoted anywhere
- [ ] **Interface and packaging** — abstention below a relevance floor, and a
      Dockerfile plus compose file

## 🤝 Contributing

This is a portfolio project demonstrating:
- RAG architecture implementation
- Vector database usage
- Claude AI integration
- Security domain expertise
- Production-ready API design

Built by **Jace Griffith** as part of AI Security Engineering portfolio.

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

## 📧 Contact

- **GitHub**: [@Griff-Reaper](https://github.com/Griff-Reaper)
- **LinkedIn**: [Jace Griffith](https://www.linkedin.com/in/jace-griffith-jg11/)

## 🙏 Acknowledgments

- **Anthropic** for Claude API
- **ChromaDB** for vector database
- **Sentence Transformers** for embeddings
- **FastAPI** for excellent web framework
- Security community for CVE and threat intelligence data

---

**Built with ❤️ for the security community**

*Demonstrating practical AI applications in cybersecurity operations*

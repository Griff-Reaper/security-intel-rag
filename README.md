# Security Intelligence RAG System

> AI-powered security intelligence platform using Retrieval Augmented Generation (RAG) with Claude API and vector search

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Anthropic Claude](https://img.shields.io/badge/Claude-Opus%205-orange.svg)](https://www.anthropic.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Project status.** The corpus is the full NVD CVE dataset — see
> [Corpus](#-corpus) for exact counts, source and pull date, all recorded in the
> committed [provenance manifest](data/manifest.json). Retrieval is
> dense-vector only, and **retrieval quality has not been measured yet** — there
> are no accuracy numbers in this README because none have been produced.
> Hybrid retrieval, exploitation enrichment, and a measured evaluation harness
> are the next steps; see [Roadmap](#-roadmap).

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

- 🔍 **Semantic Search**: Find relevant vulnerabilities using natural language
- 🤖 **AI-Powered Analysis**: Claude provides expert security analysis
- 📊 **Source Citations**: Answers carry the CVE and threat IDs of the retrieved
  documents, taken from stored metadata rather than from generated text
- 🎯 **Filtered Queries**: Restrict retrieval by severity and by document type
  (CVE vs threat intelligence)
- 🚀 **REST API**: Easy integration with SIEM, SOAR, and custom tools
- 💰 **Cost-Effective**: Local embeddings (free) + Claude API (pay-per-use)

Lexical/keyword matching, CVE-ID lookup, and reranking are **not** implemented
yet — retrieval is currently dense-vector similarity only.

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
                     ▼
              ChromaDB (cosine)  +  data/manifest.json
```

**Query** (online):

```text
┌─────────────────────────────────────────────────────────────┐
│                    User Query                                │
│            "What vulnerabilities affect VMware?"             │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              Embedding Service (Sentence Transformers)       │
│              Converts query to 384-dim vector                │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              ChromaDB Vector Database                        │
│              Cosine similarity over the NVD CVE corpus       │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              Context Formatter                               │
│              Prepares retrieved docs for Claude              │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              Claude API (Anthropic)                          │
│              Generates informed answer with analysis         │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│              Response with Sources                           │
│              Answer + CVE IDs + Threat Actors                │
└─────────────────────────────────────────────────────────────┘
```

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

## 🛠️ Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **LLM** | Claude Opus 5 (Anthropic) | Intelligent analysis and generation |
| **Embeddings** | Sentence Transformers (all-MiniLM-L6-v2) | Free, fast semantic embeddings (384-dim) |
| **Vector Database** | ChromaDB | Local persistent vector storage |
| **API Framework** | FastAPI | Modern async Python web framework |
| **Testing** | Pytest | Unit tests |

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

Example session (illustrative — the shape of the output, not a captured
transcript; the CVE and threat IDs shown are real records in [data/](data/)):

```text
Your question: What vulnerabilities affect Citrix?

ANSWER:
[Claude's analysis, grounded in the retrieved documents]

SOURCES (2 documents used):
1. [CVE] CVE-2023-4966: Citrix Bleed - Session Hijacking Vulnerability
   Severity: CRITICAL
2. [Threat Intelligence] THREAT-2024-002: LockBit 3.0 Ransomware Campaign Intensifies
```

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

**Filtered Query (CVEs only, Critical severity):**
```bash
curl -X POST "http://localhost:8000/query" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "What mitigations exist for authentication bypass?",
    "severity_filter": "CRITICAL",
    "cve_only": true,
    "query_type": "mitigation"
  }'
```

**Health Check:**
```bash
curl http://localhost:8000/health
```

### Python SDK Usage

Use the RAG system programmatically:

```python
from src.query import SecurityRAG

# Initialize
rag = SecurityRAG()

# Simple query
result = rag.query("What are the latest ransomware threats?")
print(result["answer"])

# Advanced query with filters
result = rag.query_with_filters(
    question="Tell me about critical Exchange vulnerabilities",
    severity="CRITICAL",
    cve_only=True
)
```

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
│   ├── ingest.py                # Legacy sample-data loader (demo only)
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
│   ├── identifier_queries.py    # Measures dense-only weakness on CVE IDs
│   └── results/                 # Committed JSON output of the above
│
├── tests/                       # Unit tests
│   ├── test_rag.py              # Embedding + formatting tests
│   ├── test_nvd_normalize.py    # Normalization, CVSS, CPE, filtering
│   └── test_nvd_sources.py      # Feed verification + API windowing
│
└── chroma_db/                   # Vector database (generated, gitignored)
```

The vector index is **not** committed. A collection of this size cannot be
meaningfully reviewed in a repository, so the ingestion scripts plus
[data/manifest.json](data/manifest.json) are the committed artifacts — they let
anyone rebuild the exact corpus and check the numbers.

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
| **Claude API** | Metered | Billed per token — see [current pricing](https://platform.claude.com/docs/en/pricing) |

Only the Claude API call costs money; retrieval and embedding are entirely local.
Per-query cost and latency depend on corpus size and how many documents are
retrieved, and are **not yet measured for this project** — no figures are quoted
here until they come from a committed, re-runnable benchmark.

## 📈 Performance

Not yet measured. A benchmark harness (retrieval accuracy, ablations, latency
percentiles, refusal behaviour) is planned — see [Roadmap](#-roadmap). No
performance numbers will appear in this README until they are produced by a
committed script that anyone can re-run.

## 🔮 Roadmap

Planned, in order:

- [ ] **Real corpus** — replace the sample data with the full NVD dataset via
      bulk feeds, with a committed provenance manifest (source, pull date,
      record counts) and resumable, batched ingestion
- [ ] **Hybrid retrieval** — dense + BM25 with reciprocal rank fusion, direct
      CVE-ID lookup, metadata pre-filtering, and cross-encoder reranking
      (each behind a flag so its contribution stays separately measurable)
- [ ] **Exploitation enrichment** — join CISA KEV and FIRST EPSS by CVE ID so
      results can be prioritised by real-world exploitation, not just CVSS
- [ ] **Evaluation** — Recall@k and MRR on a committed eval set, a dense vs
      hybrid vs hybrid+rerank ablation, groundedness judging, refusal rate on
      unanswerable questions, and p50/p95 latency
- [ ] **Interface and packaging** — metadata-derived citations, abstention below
      a relevance floor, and a Dockerfile plus compose file

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

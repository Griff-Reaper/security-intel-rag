# Security Intelligence RAG System

> AI-powered security intelligence platform using Retrieval Augmented Generation (RAG) with Claude API and vector search

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Anthropic Claude](https://img.shields.io/badge/Claude-Opus%205-orange.svg)](https://www.anthropic.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Project status.** This is an early build running against a small sample
> corpus (8 CVEs and 5 threat intelligence reports, both committed under
> [data/](data/)). Retrieval is dense-vector only, and **retrieval quality has
> not been measured yet** — there are no accuracy numbers in this README because
> none have been produced. A real NVD corpus, hybrid retrieval, exploitation
> enrichment, and a measured evaluation harness are the planned next steps; see
> [Roadmap](#-roadmap).

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
│              Finds most similar documents                    │
│              (CVEs, Threat Intel)                            │
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

5. **Ingest data**
```bash
python src/ingest.py
```

This loads the committed sample data (8 CVEs and 5 threat intelligence reports)
into a local ChromaDB store under `chroma_db/`. The first run also downloads the
embedding model. Ingestion is idempotent — re-running it upserts rather than
failing on duplicate IDs.

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
│   ├── ingest.py                # Data ingestion pipeline
│   ├── query.py                 # RAG query engine
│   └── api.py                   # FastAPI REST service
│
├── config/                      # Configuration
│   └── prompts.py               # Claude system prompts
│
├── data/                        # Sample security data
│   ├── sample_cves.json         # 8 CVE records
│   └── threat_intel.json        # 5 threat intelligence reports
│
├── tests/                       # Unit tests
│   └── test_rag.py              # RAG system tests
│
└── chroma_db/                   # Vector database (generated, gitignored)
```

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

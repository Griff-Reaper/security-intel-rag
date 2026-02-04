# Security Intelligence RAG System

> AI-powered security intelligence platform using Retrieval Augmented Generation (RAG) with Claude API and vector search

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Anthropic Claude](https://img.shields.io/badge/Claude-Sonnet%204-orange.svg)](https://www.anthropic.com/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109-green.svg)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

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
- 📊 **Source Citations**: Every answer includes source documents
- 🎯 **Filtered Queries**: Search by severity, type (CVE/threat intel), or keywords
- 🚀 **REST API**: Easy integration with SIEM, SOAR, and custom tools
- 💰 **Cost-Effective**: Local embeddings (free) + Claude API (pay-per-use)

## 🏗️ Architecture

```
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
| **LLM** | Claude Sonnet 4 (Anthropic) | Intelligent analysis and generation |
| **Embeddings** | Sentence Transformers (all-MiniLM-L6-v2) | Free, fast semantic embeddings |
| **Vector Database** | ChromaDB | Local persistent vector storage |
| **API Framework** | FastAPI | Modern async Python web framework |
| **Data Processing** | Pandas | Security data manipulation |
| **Testing** | Pytest | Unit and integration tests |

## 📦 Installation

### Prerequisites

- Python 3.11 or higher
- Anthropic API key ([get one here](https://console.anthropic.com/))
- 2GB disk space (for models and database)

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/security-intel-rag.git
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

This loads the sample CVE and threat intelligence data into ChromaDB (~30 seconds).

## 🚀 Usage

### Command Line Interface

Interactive query interface:

```bash
python src/query.py
```

Example session:
```
❓ Your question: What vulnerabilities affect Citrix?

📝 ANSWER:
Based on the retrieved security documents, there is a critical vulnerability 
affecting Citrix NetScaler ADC and Gateway known as "Citrix Bleed" (CVE-2023-4966).

[Full analysis with MITRE techniques, IOCs, and mitigations...]

📚 SOURCES (2 documents used):
1. [CVE] CVE-2023-4966: Citrix Bleed - Session Hijacking Vulnerability
   Severity: CRITICAL
2. [Threat Intelligence] THREAT-2024-002: LockBit 3.0 exploiting Citrix
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

```
security-intel-rag/
├── README.md                    # This file
├── requirements.txt             # Python dependencies
├── .env.example                 # Environment variables template
├── .gitignore                   # Git ignore rules
│
├── src/                         # Source code
│   ├── __init__.py
│   ├── embeddings.py            # Embedding generation service
│   ├── ingest.py                # Data ingestion pipeline
│   ├── query.py                 # RAG query engine
│   └── api.py                   # FastAPI REST service
│
├── config/                      # Configuration
│   └── prompts.py               # Claude system prompts
│
├── data/                        # Sample security data
│   ├── sample_cves.json         # CVE vulnerability data
│   └── threat_intel.json        # Threat intelligence feeds
│
├── tests/                       # Unit tests
│   ├── __init__.py
│   └── test_rag.py              # RAG system tests
│
├── notebooks/                   # Jupyter notebooks
│   └── demo.ipynb               # Interactive demo
│
└── chroma_db/                   # Vector database (generated)
    └── [ChromaDB files]
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

## 💰 Cost Analysis

| Component | Cost | Notes |
|-----------|------|-------|
| **Embeddings** | FREE | Sentence Transformers runs locally |
| **Vector Database** | FREE | ChromaDB is open-source |
| **Claude API** | ~$0.015/query | Sonnet 4: $3/MTok input, $15/MTok output |

**Estimated monthly cost for 1000 queries:** $15-20

Compare to:
- OpenAI GPT-4: ~$30-40/month for same usage
- Hosted vector DB (Pinecone): $70+/month
- Commercial security intelligence platforms: $1000+/month

## 📈 Performance

| Metric | Value | Notes |
|--------|-------|-------|
| **Query Latency** | 2-4 seconds | Including retrieval + Claude API |
| **Embedding Speed** | ~50 docs/second | On CPU |
| **Database Size** | ~10MB | For 100 documents |
| **Memory Usage** | ~500MB | Including loaded model |

## 🔮 Future Enhancements

Planned features for v2:

- [ ] Real-time CVE feed integration (NVD API)
- [ ] Multi-language support (embeddings + Claude)
- [ ] Advanced filtering (date ranges, CVSS scores)
- [ ] LangChain agent integration for complex queries
- [ ] Monitoring dashboard (Grafana)
- [ ] Automated threat report generation
- [ ] Integration with SIEM platforms (Splunk, Sumo Logic)
- [ ] Docker containerization
- [ ] Azure OpenAI embeddings option (for enterprise)

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

- **GitHub**: [@YOUR_USERNAME](https://github.com/YOUR_USERNAME)
- **LinkedIn**: [Your LinkedIn](https://linkedin.com/in/YOUR_PROFILE)
- **Email**: joygriff1@yahoo.com

## 🙏 Acknowledgments

- **Anthropic** for Claude API
- **ChromaDB** for vector database
- **Sentence Transformers** for embeddings
- **FastAPI** for excellent web framework
- Security community for CVE and threat intelligence data

---

**Built with ❤️ for the security community**

*Demonstrating practical AI applications in cybersecurity operations*

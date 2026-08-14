"""
RAG Query Engine - Retrieval Augmented Generation for Security Intelligence

This is the core of the RAG system:
1. User asks a question
2. We retrieve relevant security documents from ChromaDB
3. We send the documents + question to Claude
4. Claude generates an informed answer based on the retrieved context

This prevents hallucinations because Claude only answers based on
the actual security data we've ingested.
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import chromadb
from chromadb.config import Settings
from dotenv import load_dotenv

# Resolve sibling packages relative to this file rather than the working
# directory, so the module works both as a script (`python src/query.py`) and
# as an import (`from src.query import SecurityRAG`), from any directory.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
for _path in (PROJECT_ROOT / "src", PROJECT_ROOT / "config"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

DEFAULT_PERSIST_DIRECTORY = str(PROJECT_ROOT / "chroma_db")
# The NVD corpus built by src/ingest_nvd.py. Overridable via COLLECTION_NAME.
DEFAULT_COLLECTION_NAME = "nvd_cve"
DEFAULT_LEXICAL_DB = str(PROJECT_ROOT / "chroma_db" / "lexical.sqlite3")

# The configuration the ablation measured best on product + version queries,
# which is the realistic query shape. See README "Measured behaviour" and
# experiments/results/identifier_queries_*.json. Overridable via RETRIEVAL_MODE
# so the weaker, faster configurations stay reachable without a code change.
DEFAULT_RETRIEVAL_MODE = "hybrid_rerank"

import claude_client
import filters as filters_mod
import lexical_index as LX
import retrieval as retrieval_mod
from embeddings import EmbeddingService
from prompts import (
    SECURITY_ANALYST_SYSTEM_PROMPT,
    get_prompt_template,
    format_context_documents
)


class SecurityRAG:
    """
    Retrieval Augmented Generation system for security intelligence.
    
    The RAG process:
    Query -> Embed -> Retrieve relevant docs -> Format prompt -> Claude -> Answer
    """
    
    def __init__(
        self,
        persist_directory: str = DEFAULT_PERSIST_DIRECTORY,
        collection_name: Optional[str] = None,
        retrieval: Optional[str] = None,
        lexical_db: Optional[str] = None,
        direct_id: bool = True,
    ):
        """
        Initialize the RAG system.

        Args:
            persist_directory: Where ChromaDB is stored
            collection_name: Which collection to query
            retrieval: One of retrieval.MODES. Defaults to RETRIEVAL_MODE in the
                environment, else DEFAULT_RETRIEVAL_MODE.
            lexical_db: Path to the FTS5 index. Required by every mode except
                `dense`, and by direct-ID routing.
            direct_id: Route exact CVE identifiers to a keyed lookup.
        """
        # Load environment variables (API keys)
        load_dotenv()

        collection_name = (
            collection_name
            or os.getenv("COLLECTION_NAME")
            or DEFAULT_COLLECTION_NAME
        )

        # Checked construction: an SDK too old to parse thinking blocks fails
        # here with an actionable message rather than as an AttributeError deep
        # in response parsing on the first query. See src/claude_client.py.
        self.claude = claude_client.build_client()
        self.model = os.getenv("CLAUDE_MODEL", "claude-opus-5")
        self.max_tokens = int(os.getenv("MAX_TOKENS", "4096"))

        # Initialize ChromaDB client. Must be PersistentClient to read what
        # ingest.py wrote; chromadb.Client() is in-memory and would always
        # come up empty.
        print(f"Connecting to ChromaDB at: {persist_directory}")
        self.client = chromadb.PersistentClient(
            path=persist_directory,
            settings=Settings(anonymized_telemetry=False)
        )

        # Get collection
        try:
            self.collection = self.client.get_collection(name=collection_name)
            count = self.collection.count()
            print(f"[OK] Connected to collection '{collection_name}' ({count} documents)")
        except Exception as e:
            raise ValueError(f"Collection '{collection_name}' not found. Run ingest.py first! Error: {e}")
        
        # Initialize embedding service (for query embedding)
        self.embedding_service = EmbeddingService()

        # Retrieval backend. This is the same code experiments/identifier_queries.py
        # measures, so the numbers in the README describe what actually runs here.
        self.retrieval_mode = (
            retrieval or os.getenv("RETRIEVAL_MODE") or DEFAULT_RETRIEVAL_MODE
        )
        self.lexical_db = lexical_db or os.getenv("LEXICAL_DB") or DEFAULT_LEXICAL_DB
        # Direct CVE-ID routing is on by default. Ranked retrieval cannot place
        # the best-known CVEs first for their own identifiers - see the
        # cross-reference split in the README - and a keyed lookup can.
        self.direct_id = direct_id
        self.lexical_conn = None
        if self.retrieval_mode != "dense" or self.direct_id:
            # Fail loudly rather than falling back to dense: a silent downgrade
            # would serve measurably worse results while the README described
            # the better ones.
            self.lexical_conn = LX.connect(Path(self.lexical_db), read_only=True)
            lexical_count = LX.document_count(self.lexical_conn)
            if lexical_count != count:
                raise ValueError(
                    f"lexical index has {lexical_count:,} documents but collection "
                    f"'{collection_name}' has {count:,}. Rebuild with: "
                    f"python src/build_fts.py"
                )
        routing = " + direct CVE-ID routing" if self.direct_id else ""
        print(f"[OK] Retrieval: {self.retrieval_mode}{routing}")

    def _retriever(self, filters: Optional[Dict[str, Any]]):
        """Get a retriever for this filter spec, reusing the last one if it matches.

        Retrievers are cached rather than rebuilt per call because constructing
        one for a packed-list filter resolves an ID allow-list against the
        lexical index, which is the expensive part of filtering (about a second
        for a vendor matching 26,000 records).
        """
        key = filters_mod.describe(filters)
        cached = getattr(self, "_retriever_cache", None)
        if cached is None or cached[0] != key:
            self._retriever_cache = (
                key,
                retrieval_mod.build_retriever(
                    self.retrieval_mode,
                    collection=self.collection,
                    embedder=self.embedding_service,
                    lexical_conn=self.lexical_conn,
                    filters=filters,
                    direct_id=self.direct_id,
                ),
            )
        return self._retriever_cache[1]

    def retrieve_context(
        self,
        query: str,
        n_results: int = 5,
        filters: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Retrieve relevant documents.

        This is the "Retrieval" part of RAG.

        Args:
            query: The user's question
            n_results: How many relevant documents to retrieve
            filters: Optional metadata pre-filter, e.g.
                {"severity": "CRITICAL", "vendor": "apache", "min_cvss": 9.0}.
                See src/filters.py for the supported fields. Filters are applied
                before ranking, so n_results returns that many *matching*
                documents rather than however many of the top n happen to match.

        Returns:
            Dictionary with documents, metadatas, ranks and n_results.

        Note there is no similarity score in the return value. Each backend
        scores on its own scale - cosine distance, BM25, an RRF sum, a
        cross-encoder logit - and presenting whichever one happened to run under
        a single name would invite comparisons between numbers that do not share
        a meaning. Rank is well defined for all of them.
        """
        ranked_ids = self._retriever(filters).search(query, n_results)
        if not ranked_ids:
            return {"documents": [], "metadatas": [], "ranks": [], "n_results": 0}

        fetched = self.collection.get(
            ids=ranked_ids, include=["documents", "metadatas"]
        )
        by_id = {
            doc_id: (document, metadata)
            for doc_id, document, metadata
            in zip(fetched["ids"], fetched["documents"], fetched["metadatas"])
        }

        # Chroma returns rows in its own order; restore the ranking.
        documents, metadatas, ranks = [], [], []
        for rank, doc_id in enumerate(ranked_ids, start=1):
            if doc_id not in by_id:
                continue
            document, metadata = by_id[doc_id]
            documents.append(document)
            metadatas.append(metadata)
            ranks.append(rank)

        return {
            "documents": documents,
            "metadatas": metadatas,
            "ranks": ranks,
            "n_results": len(documents),
        }

    def query(
        self,
        question: str,
        n_results: int = 5,
        query_type: str = "general",
        filters: Optional[Dict[str, Any]] = None,
        return_context: bool = False
    ) -> Dict[str, Any]:
        """
        Main query function - the complete RAG pipeline.

        Args:
            question: User's security question
            n_results: How many documents to retrieve
            query_type: Type of query (cve, threat, summary, etc.)
            filters: Optional metadata pre-filter; see src/filters.py
            return_context: Whether to include retrieved documents in response
            
        Returns:
            Dictionary with answer, sources, and optionally context
        """
        print(f"\n Processing query: {question}")
        
        # Step 1: Retrieve relevant context
        print(f"Retrieving {n_results} relevant documents...")
        context_results = self.retrieve_context(
            query=question,
            n_results=n_results,
            filters=filters
        )
        
        if context_results["n_results"] == 0:
            return {
                "answer": "I couldn't find any relevant security information for your query in the database.",
                "sources": [],
                "error": "No relevant documents found"
            }
        
        print(f"[OK] Retrieved {context_results['n_results']} documents")
        
        # Step 2: Format the context for Claude
        formatted_context = format_context_documents(
            context_results["documents"],
            context_results["metadatas"]
        )
        
        # Step 3: Get appropriate prompt template
        prompt_template = get_prompt_template(query_type)
        
        # Fill in the template with actual context and query
        user_prompt = prompt_template.format(
            context=formatted_context,
            query=question
        )
        
        # Step 4: Call Claude API
        print("Generating answer with Claude...")
        try:
            # No temperature/top_p/top_k: those parameters are rejected with a
            # 400 on current Claude models. Steer behaviour with the prompt.
            response = self.claude.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SECURITY_ANALYST_SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )

            # Safety classifiers can decline a request: HTTP 200 with
            # stop_reason "refusal" and empty/partial content. Check before
            # indexing into content.
            if response.stop_reason == "refusal":
                return {
                    "answer": "The model declined to answer this query.",
                    "sources": [],
                    "error": "refusal",
                }

            answer = next(
                (b.text for b in response.content if b.type == "text"), ""
            )
            print("[OK] Answer generated")

        except Exception as e:
            print(f"[ERROR] Error calling Claude API: {e}")
            return {
                "answer": f"Error generating response: {str(e)}",
                "sources": [],
                "error": str(e)
            }
        
        # Step 5: Prepare response
        # Citations are built from stored metadata, never from the generated
        # text: a model asked to name its sources will invent plausible CVE IDs.
        sources = []
        for meta, rank in zip(context_results["metadatas"], context_results["ranks"]):
            if meta.get("type") == "cve":
                sources.append({
                    "type": "CVE",
                    "id": meta.get("cve_id"),
                    "severity": meta.get("severity") or None,
                    "cvss_base_score": meta.get("cvss_base_score"),
                    "published": meta.get("published") or None,
                    "vendors": meta.get("vendors") or None,
                    "products": meta.get("products") or None,
                    # Exploitation signals, absent when the record predates the
                    # last enrichment pass rather than defaulted to False.
                    "kev": meta.get("kev"),
                    "kev_ransomware": meta.get("kev_ransomware"),
                    "epss_score": meta.get("epss_score"),
                    "epss_percentile": meta.get("epss_percentile"),
                    "rank": rank,
                })
            elif meta.get("type") == "threat_intel":
                sources.append({
                    "type": "Threat Intelligence",
                    "id": meta.get("threat_id"),
                    "title": meta.get("title"),
                    "threat_actor": meta.get("threat_actor"),
                    "severity": meta.get("severity") or None,
                    "rank": rank,
                })

        result = {
            "answer": answer,
            "sources": sources,
            "n_sources": len(sources)
        }
        
        # Optionally include the raw retrieved context
        if return_context:
            result["context"] = formatted_context
        
        return result
    
    def query_with_filters(
        self,
        question: str,
        severity: Optional[Any] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        cwe: Optional[str] = None,
        min_cvss: Optional[float] = None,
        published_after: Optional[int] = None,
        kev: Optional[bool] = None,
        kev_ransomware: Optional[bool] = None,
        min_epss: Optional[float] = None,
        min_epss_percentile: Optional[float] = None,
        n_results: int = 5,
    ) -> Dict[str, Any]:
        """
        Convenience method for the filters an analyst actually narrows by.

        Args:
            question: User's question
            severity: One severity or a list of them (CRITICAL, HIGH, MEDIUM, LOW)
            vendor: Affected vendor, matched as a whole name
            product: Affected product, matched as a whole name
            cwe: CWE identifier, e.g. "CWE-502"
            min_cvss: Minimum CVSS base score
            published_after: Epoch seconds
            kev: Restrict to CISA KEV listings (confirmed exploitation)
            kev_ransomware: Restrict to KEV entries linked to ransomware campaigns
            min_epss: Minimum EPSS probability, in [0, 1]
            min_epss_percentile: Minimum EPSS percentile, in [0, 1]. Not the same
                question as min_epss - a 0.034 score can sit at the 88th
                percentile.
            n_results: How many documents to retrieve

        Returns:
            Query results
        """
        spec: Dict[str, Any] = {}
        for key, value in (
            ("severity", severity), ("vendor", vendor), ("product", product),
            ("cwe", cwe), ("min_cvss", min_cvss),
            ("published_after", published_after), ("kev", kev),
            ("kev_ransomware", kev_ransomware), ("min_epss", min_epss),
            ("min_epss_percentile", min_epss_percentile),
        ):
            if value is not None:
                spec[key] = value

        return self.query(
            question=question,
            filters=spec or None,
            n_results=n_results,
        )


# Interactive CLI for testing
def main():
    """
    Interactive command-line interface for testing the RAG system.
    """
    print("=" * 70)
    print("Security Intelligence RAG System")
    print("=" * 70)
    print("\nInitializing...")
    
    try:
        rag = SecurityRAG()
    except Exception as e:
        print(f"[ERROR] Error initializing RAG system: {e}")
        print("\nMake sure you have:")
        print("1. Run 'python src/ingest.py' to load data")
        print("2. Set ANTHROPIC_API_KEY in your .env file")
        return
    
    print("\n[OK] System ready!")
    print("\nExample queries:")
    print("- What vulnerabilities affect Citrix?")
    print("- Tell me about APT29 threat actor")
    print("- What are the critical CVEs in the database?")
    print("- How should I respond to ransomware attacks?")
    print("\nType 'quit' to exit\n")
    
    while True:
        try:
            # Get user input
            question = input("\n Your question: ").strip()
            
            if not question:
                continue
            
            if question.lower() in ['quit', 'exit', 'q']:
                print("\n Goodbye!")
                break
            
            # Process query
            result = rag.query(question, n_results=3)
            
            # Display results
            print("\n" + "=" * 70)
            print("ANSWER:")
            print("=" * 70)
            print(result["answer"])
            
            print("\n" + "=" * 70)
            print(f"SOURCES ({result['n_sources']} documents used):")
            print("=" * 70)
            for i, source in enumerate(result["sources"], 1):
                header = f"{i}. [{source['type']}] {source.get('id') or 'N/A'}"
                if source.get("title"):
                    header += f": {source['title']}"
                print(header)
                if source.get("severity"):
                    score = source.get("cvss_base_score")
                    score_text = f" (CVSS {score})" if score is not None else ""
                    print(f"   Severity: {source['severity']}{score_text}")
                if source.get("products"):
                    print(f"   Products: {source['products'].replace('|', ', ')}")
                if source.get("threat_actor"):
                    print(f"   Actor: {source['threat_actor']}")
                if source.get("rank") is not None:
                    print(f"   Rank: {source['rank']}")
            
        except KeyboardInterrupt:
            print("\n\n Goodbye!")
            break
        except Exception as e:
            print(f"\n[ERROR] Error: {e}")


if __name__ == "__main__":
    main()

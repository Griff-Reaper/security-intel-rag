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
from anthropic import Anthropic
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
        collection_name: Optional[str] = None
    ):
        """
        Initialize the RAG system.
        
        Args:
            persist_directory: Where ChromaDB is stored
            collection_name: Which collection to query
        """
        # Load environment variables (API keys)
        load_dotenv()

        collection_name = (
            collection_name
            or os.getenv("COLLECTION_NAME")
            or DEFAULT_COLLECTION_NAME
        )

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment!")
        
        # Initialize Claude client
        self.claude = Anthropic(api_key=api_key)
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
        
    def retrieve_context(
        self,
        query: str,
        n_results: int = 5,
        filter_metadata: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """
        Retrieve relevant documents from the vector database.
        
        This is the "Retrieval" part of RAG.
        
        Args:
            query: The user's question
            n_results: How many relevant documents to retrieve
            filter_metadata: Optional filters (e.g., {"severity": "CRITICAL"})
            
        Returns:
            Dictionary with documents, metadatas, and distances
        """
        # Convert query to embedding
        query_embedding = self.embedding_service.get_embedding(query)
        
        # Search the vector database
        # ChromaDB finds documents with embeddings most similar to the query
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=filter_metadata  # Optional filtering
        )
        
        return {
            "documents": results["documents"][0],  # The actual text
            "metadatas": results["metadatas"][0],  # Structured data
            "distances": results["distances"][0],  # Similarity scores (lower = more similar)
            "n_results": len(results["documents"][0])
        }
    
    def query(
        self,
        question: str,
        n_results: int = 5,
        query_type: str = "general",
        filter_metadata: Optional[Dict] = None,
        return_context: bool = False
    ) -> Dict[str, Any]:
        """
        Main query function - the complete RAG pipeline.
        
        Args:
            question: User's security question
            n_results: How many documents to retrieve
            query_type: Type of query (cve, threat, summary, etc.)
            filter_metadata: Optional filters for retrieval
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
            filter_metadata=filter_metadata
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
        for meta, distance in zip(
            context_results["metadatas"], context_results["distances"]
        ):
            if meta.get("type") == "cve":
                sources.append({
                    "type": "CVE",
                    "id": meta.get("cve_id"),
                    "severity": meta.get("severity") or None,
                    "cvss_base_score": meta.get("cvss_base_score"),
                    "published": meta.get("published") or None,
                    "vendors": meta.get("vendors") or None,
                    "products": meta.get("products") or None,
                    "distance": round(float(distance), 4),
                })
            elif meta.get("type") == "threat_intel":
                sources.append({
                    "type": "Threat Intelligence",
                    "id": meta.get("threat_id"),
                    "title": meta.get("title"),
                    "threat_actor": meta.get("threat_actor"),
                    "severity": meta.get("severity") or None,
                    "distance": round(float(distance), 4),
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
        severity: Optional[str] = None,
        cve_only: bool = False,
        threat_only: bool = False
    ) -> Dict[str, Any]:
        """
        Convenience method for common filtering patterns.
        
        Args:
            question: User's question
            severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)
            cve_only: Only retrieve CVE documents
            threat_only: Only retrieve threat intelligence
            
        Returns:
            Query results
        """
        filter_metadata = {}
        
        if severity:
            filter_metadata["severity"] = severity
        
        if cve_only:
            filter_metadata["type"] = "cve"
        elif threat_only:
            filter_metadata["type"] = "threat_intel"
        
        return self.query(
            question=question,
            filter_metadata=filter_metadata if filter_metadata else None
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
                if source.get("distance") is not None:
                    print(f"   Distance: {source['distance']}")
            
        except KeyboardInterrupt:
            print("\n\n Goodbye!")
            break
        except Exception as e:
            print(f"\n[ERROR] Error: {e}")


if __name__ == "__main__":
    main()

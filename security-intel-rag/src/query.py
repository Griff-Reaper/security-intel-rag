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
from typing import List, Dict, Any, Optional
from anthropic import Anthropic
import chromadb
from chromadb.config import Settings
from dotenv import load_dotenv

from embeddings import EmbeddingService
import sys
sys.path.append('config')
from prompts import (
    SECURITY_ANALYST_SYSTEM_PROMPT,
    get_prompt_template,
    format_context_documents
)


class SecurityRAG:
    """
    Retrieval Augmented Generation system for security intelligence.
    
    The RAG process:
    Query → Embed → Retrieve relevant docs → Format prompt → Claude → Answer
    """
    
    def __init__(
        self,
        persist_directory: str = "./chroma_db",
        collection_name: str = "security_intel"
    ):
        """
        Initialize the RAG system.
        
        Args:
            persist_directory: Where ChromaDB is stored
            collection_name: Which collection to query
        """
        # Load environment variables (API keys)
        load_dotenv()
        
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment!")
        
        # Initialize Claude client
        self.claude = Anthropic(api_key=api_key)
        self.model = os.getenv("CLAUDE_MODEL", "claude-sonnet-4-20250514")
        self.max_tokens = int(os.getenv("MAX_TOKENS", "4096"))
        self.temperature = float(os.getenv("TEMPERATURE", "0.3"))
        
        # Initialize ChromaDB client
        print(f"Connecting to ChromaDB at: {persist_directory}")
        self.client = chromadb.Client(Settings(
            persist_directory=persist_directory,
            anonymized_telemetry=False
        ))
        
        # Get collection
        try:
            self.collection = self.client.get_collection(name=collection_name)
            count = self.collection.count()
            print(f"✓ Connected to collection '{collection_name}' ({count} documents)")
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
        print(f"\n🔍 Processing query: {question}")
        
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
        
        print(f"✓ Retrieved {context_results['n_results']} documents")
        
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
            response = self.claude.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                system=SECURITY_ANALYST_SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": user_prompt}
                ]
            )
            
            answer = response.content[0].text
            print("✓ Answer generated")
            
        except Exception as e:
            print(f"❌ Error calling Claude API: {e}")
            return {
                "answer": f"Error generating response: {str(e)}",
                "sources": [],
                "error": str(e)
            }
        
        # Step 5: Prepare response
        # Extract source information for citations
        sources = []
        for meta in context_results["metadatas"]:
            if meta.get("type") == "cve":
                sources.append({
                    "type": "CVE",
                    "id": meta.get("cve_id"),
                    "title": meta.get("title"),
                    "severity": meta.get("severity")
                })
            elif meta.get("type") == "threat_intel":
                sources.append({
                    "type": "Threat Intelligence",
                    "id": meta.get("threat_id"),
                    "title": meta.get("title"),
                    "threat_actor": meta.get("threat_actor")
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
        print(f"❌ Error initializing RAG system: {e}")
        print("\nMake sure you have:")
        print("1. Run 'python src/ingest.py' to load data")
        print("2. Set ANTHROPIC_API_KEY in your .env file")
        return
    
    print("\n✓ System ready!")
    print("\nExample queries:")
    print("  - What vulnerabilities affect Citrix?")
    print("  - Tell me about APT29 threat actor")
    print("  - What are the critical CVEs in the database?")
    print("  - How should I respond to ransomware attacks?")
    print("\nType 'quit' to exit\n")
    
    while True:
        try:
            # Get user input
            question = input("\n❓ Your question: ").strip()
            
            if not question:
                continue
            
            if question.lower() in ['quit', 'exit', 'q']:
                print("\n👋 Goodbye!")
                break
            
            # Process query
            result = rag.query(question, n_results=3)
            
            # Display results
            print("\n" + "=" * 70)
            print("📝 ANSWER:")
            print("=" * 70)
            print(result["answer"])
            
            print("\n" + "=" * 70)
            print(f"📚 SOURCES ({result['n_sources']} documents used):")
            print("=" * 70)
            for i, source in enumerate(result["sources"], 1):
                print(f"{i}. [{source['type']}] {source.get('id', 'N/A')}: {source.get('title', 'N/A')}")
                if 'severity' in source:
                    print(f"   Severity: {source['severity']}")
                if 'threat_actor' in source:
                    print(f"   Actor: {source['threat_actor']}")
            
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            break
        except Exception as e:
            print(f"\n❌ Error: {e}")


if __name__ == "__main__":
    main()

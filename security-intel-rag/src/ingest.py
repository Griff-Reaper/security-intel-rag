"""
Data Ingestion Pipeline - Load security data into ChromaDB vector database

This module:
1. Loads CVE and threat intelligence data from JSON files
2. Converts them into searchable documents
3. Generates embeddings for semantic search
4. Stores everything in ChromaDB for fast retrieval

The ingestion process:
Data (JSON) → Document format → Embeddings → ChromaDB → Ready for queries!
"""

import json
import os
from typing import List, Dict, Any
from datetime import datetime
import chromadb
from chromadb.config import Settings
from tqdm import tqdm

from embeddings import EmbeddingService


class SecurityDataIngester:
    """
    Handles ingestion of security data into the vector database.
    
    ChromaDB stores:
    - documents: The text content we want to search
    - embeddings: Vector representations for semantic search
    - metadata: Additional info (severity, date, etc.) for filtering
    - ids: Unique identifiers for each document
    """
    
    def __init__(self, persist_directory: str = "./chroma_db", collection_name: str = "security_intel"):
        """
        Initialize the ingester with database connection.
        
        Args:
            persist_directory: Where to store the database (local folder)
            collection_name: Name of the collection (like a table in SQL)
        """
        print(f"Initializing ChromaDB at: {persist_directory}")
        
        # Create ChromaDB client (local, persistent storage)
        self.client = chromadb.Client(Settings(
            persist_directory=persist_directory,
            anonymized_telemetry=False  # Disable analytics
        ))
        
        # Get or create collection
        # Collections in ChromaDB are like tables in a database
        try:
            self.collection = self.client.get_collection(name=collection_name)
            print(f"✓ Using existing collection: {collection_name}")
        except:
            self.collection = self.client.create_collection(
                name=collection_name,
                metadata={"description": "Security intelligence and vulnerability data"}
            )
            print(f"✓ Created new collection: {collection_name}")
        
        # Initialize embedding service
        self.embedding_service = EmbeddingService()
        
    def format_cve_document(self, cve: Dict[str, Any]) -> str:
        """
        Convert a CVE dictionary into searchable text.
        
        This creates a rich text representation that includes all important fields.
        The more context we include, the better the semantic search works.
        
        Args:
            cve: Dictionary containing CVE data
            
        Returns:
            Formatted text string for embedding
        """
        # Build a comprehensive text representation
        doc = f"""
CVE ID: {cve['id']}
Title: {cve['title']}
Severity: {cve['severity']} (CVSS: {cve['cvss_score']})
Published: {cve['published_date']}

Description:
{cve['description']}

Affected Products:
{', '.join(cve['affected_products'])}

Mitigations:
{chr(10).join(f"- {m}" for m in cve['mitigations'])}

MITRE ATT&CK Techniques:
{', '.join(cve.get('mitre_attack', []))}

CWE: {cve.get('cwe', 'N/A')}
"""
        return doc.strip()
    
    def format_threat_intel_document(self, threat: Dict[str, Any]) -> str:
        """
        Convert threat intelligence into searchable text.
        
        Args:
            threat: Dictionary containing threat intel data
            
        Returns:
            Formatted text string for embedding
        """
        doc = f"""
Threat ID: {threat['id']}
Title: {threat['title']}
Date: {threat['date']}
Threat Actor: {threat['threat_actor']}
Attribution: {threat.get('attribution', 'Unknown')}
Severity: {threat['severity']}

Description:
{threat['description']}

Tactics:
{chr(10).join(f"- {t}" for t in threat['tactics'])}

MITRE Techniques:
{', '.join(threat.get('mitre_techniques', []))}

Indicators of Compromise:
Domains: {', '.join(threat['iocs'].get('domains', []))}
IPs: {', '.join(threat['iocs'].get('ips', []))}

Recommendations:
{chr(10).join(f"- {r}" for r in threat['recommendations'])}
"""
        return doc.strip()
    
    def ingest_cves(self, json_file: str) -> int:
        """
        Load CVE data from JSON file and ingest into vector database.
        
        Args:
            json_file: Path to the JSON file containing CVE data
            
        Returns:
            Number of CVEs ingested
        """
        print(f"\n📥 Ingesting CVE data from: {json_file}")
        
        # Load JSON data
        with open(json_file, 'r') as f:
            cves = json.load(f)
        
        print(f"Found {len(cves)} CVEs to process")
        
        # Prepare data for ChromaDB
        documents = []  # Text content to search
        embeddings = []  # Vector representations
        metadatas = []  # Structured data for filtering
        ids = []        # Unique identifiers
        
        # Process each CVE
        for cve in tqdm(cves, desc="Processing CVEs"):
            # Format as searchable text
            doc_text = self.format_cve_document(cve)
            documents.append(doc_text)
            
            # Prepare metadata (for filtering queries)
            metadata = {
                "type": "cve",
                "cve_id": cve['id'],
                "severity": cve['severity'],
                "cvss_score": cve['cvss_score'],
                "published_date": cve['published_date'],
                "title": cve['title']
            }
            metadatas.append(metadata)
            
            # Use CVE ID as unique identifier
            ids.append(cve['id'])
        
        # Generate embeddings for all documents at once (efficient batching)
        print("Generating embeddings...")
        embeddings = self.embedding_service.get_embeddings(documents, show_progress=True)
        
        # Add to ChromaDB
        print("Adding to vector database...")
        self.collection.add(
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"✓ Successfully ingested {len(cves)} CVEs")
        return len(cves)
    
    def ingest_threat_intel(self, json_file: str) -> int:
        """
        Load threat intelligence from JSON file and ingest into vector database.
        
        Args:
            json_file: Path to the JSON file containing threat intel
            
        Returns:
            Number of threat reports ingested
        """
        print(f"\n📥 Ingesting threat intelligence from: {json_file}")
        
        with open(json_file, 'r') as f:
            threats = json.load(f)
        
        print(f"Found {len(threats)} threat reports to process")
        
        documents = []
        embeddings = []
        metadatas = []
        ids = []
        
        for threat in tqdm(threats, desc="Processing threats"):
            doc_text = self.format_threat_intel_document(threat)
            documents.append(doc_text)
            
            metadata = {
                "type": "threat_intel",
                "threat_id": threat['id'],
                "threat_actor": threat['threat_actor'],
                "severity": threat['severity'],
                "date": threat['date'],
                "title": threat['title']
            }
            metadatas.append(metadata)
            
            ids.append(threat['id'])
        
        print("Generating embeddings...")
        embeddings = self.embedding_service.get_embeddings(documents, show_progress=True)
        
        print("Adding to vector database...")
        self.collection.add(
            documents=documents,
            embeddings=embeddings,
            metadatas=metadatas,
            ids=ids
        )
        
        print(f"✓ Successfully ingested {len(threats)} threat reports")
        return len(threats)
    
    def get_collection_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the current collection.
        
        Returns:
            Dictionary with count and sample data
        """
        count = self.collection.count()
        
        # Get a few sample documents
        if count > 0:
            sample = self.collection.peek(limit=3)
        else:
            sample = None
        
        return {
            "total_documents": count,
            "collection_name": self.collection.name,
            "sample": sample
        }


# Main execution - run this file directly to ingest data
if __name__ == "__main__":
    print("=" * 60)
    print("Security Intelligence RAG - Data Ingestion")
    print("=" * 60)
    
    # Initialize ingester
    ingester = SecurityDataIngester()
    
    # Check if data files exist
    cve_file = "data/sample_cves.json"
    threat_file = "data/threat_intel.json"
    
    if not os.path.exists(cve_file):
        print(f"❌ Error: {cve_file} not found!")
        print("Make sure you're running from the project root directory.")
        exit(1)
    
    if not os.path.exists(threat_file):
        print(f"❌ Error: {threat_file} not found!")
        exit(1)
    
    # Ingest data
    total_cves = ingester.ingest_cves(cve_file)
    total_threats = ingester.ingest_threat_intel(threat_file)
    
    # Show statistics
    stats = ingester.get_collection_stats()
    print("\n" + "=" * 60)
    print("Ingestion Complete!")
    print("=" * 60)
    print(f"Total documents in database: {stats['total_documents']}")
    print(f"  - CVEs: {total_cves}")
    print(f"  - Threat Intel: {total_threats}")
    print("\n✓ Database is ready for queries!")

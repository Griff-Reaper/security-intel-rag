"""
Basic tests for Security Intelligence RAG System

Run with: pytest tests/test_rag.py
"""

import pytest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from embeddings import EmbeddingService


class TestEmbeddings:
    """Test embedding generation."""
    
    def test_embedding_service_initialization(self):
        """Test that embedding service initializes correctly."""
        service = EmbeddingService()
        assert service is not None
        assert service.model is not None
    
    def test_single_embedding_generation(self):
        """Test generating a single embedding."""
        service = EmbeddingService()
        text = "SQL injection vulnerability"
        embedding = service.get_embedding(text)
        
        assert isinstance(embedding, list)
        assert len(embedding) == 384  # all-MiniLM-L6-v2 dimension
        assert all(isinstance(x, float) for x in embedding)
    
    def test_batch_embedding_generation(self):
        """Test generating multiple embeddings."""
        service = EmbeddingService()
        texts = [
            "Remote code execution",
            "Cross-site scripting",
            "Authentication bypass"
        ]
        embeddings = service.get_embeddings(texts, show_progress=False)
        
        assert len(embeddings) == 3
        assert all(len(emb) == 384 for emb in embeddings)
    
    def test_empty_text_handling(self):
        """Test that empty text is handled gracefully."""
        service = EmbeddingService()
        embedding = service.get_embedding("")
        
        assert isinstance(embedding, list)
        assert len(embedding) == 384


class TestDataIngestion:
    """Test data ingestion pipeline."""
    
    def test_cve_formatting(self):
        """Test CVE document formatting."""
        from ingest import SecurityDataIngester
        
        ingester = SecurityDataIngester()
        
        test_cve = {
            "id": "CVE-2024-TEST",
            "title": "Test Vulnerability",
            "description": "This is a test",
            "severity": "HIGH",
            "cvss_score": 8.5,
            "published_date": "2024-01-01",
            "affected_products": ["Test Product"],
            "mitigations": ["Apply patches"],
            "cwe": "CWE-79",
            "mitre_attack": ["T1190"]
        }
        
        formatted = ingester.format_cve_document(test_cve)
        
        assert "CVE-2024-TEST" in formatted
        assert "Test Vulnerability" in formatted
        assert "HIGH" in formatted


# Pytest configuration
def pytest_configure(config):
    """Configure pytest."""
    print("\n" + "=" * 60)
    print("Running Security RAG System Tests")
    print("=" * 60)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

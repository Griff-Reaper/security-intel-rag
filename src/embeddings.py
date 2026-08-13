"""
Embedding Service - Converts text into vector embeddings for semantic search

This module handles:
1. Loading the embedding model (Sentence Transformers)
2. Converting security documents into numerical vectors
3. Caching for performance

Why we use sentence-transformers:
- FREE (no API costs like OpenAI)
- Fast (runs locally)
- Good quality (specifically trained for semantic similarity)
- Works offline
"""

from sentence_transformers import SentenceTransformer
from typing import List
import numpy as np


class EmbeddingService:
    """
    Service for generating embeddings from text using Sentence Transformers.
    
    The embedding model converts text into a 384-dimensional vector that captures
    the semantic meaning. Similar texts will have similar vectors (measured by cosine similarity).
    """
    
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize the embedding model.
        
        Args:
            model_name: Name of the sentence-transformer model to use
                       Default: all-MiniLM-L6-v2 (fast, 384 dimensions, good quality)
        
        The first time you run this, it downloads the model (~90MB).
        After that, it loads from cache (~1 second).
        """
        print(f"Loading embedding model: {model_name}...")
        self.model = SentenceTransformer(model_name)
        self.model_name = model_name
        print(f"[OK] Model loaded successfully!")
        
    def get_embedding(self, text: str) -> List[float]:
        """
        Convert a single text string into an embedding vector.
        
        Args:
            text: The text to embed (e.g., a CVE description)
            
        Returns:
            A list of 384 floating point numbers representing the text
            
        Example:
            >>> service = EmbeddingService()
            >>> embedding = service.get_embedding("SQL injection vulnerability")
            >>> len(embedding)
            384
        """
        if not text or text.strip() == "":
            # Return zero vector for empty text
            return [0.0] * self.get_embedding_dimension()

        # The model handles all the ML magic internally. Normalized to match
        # get_embeddings() so query and document vectors live on the same scale.
        # show_progress_bar is off because this is the per-query path: a bar for
        # a single text is pure noise on stderr and its own writes land inside
        # the interval the latency measurements are timing.
        embedding = self.model.encode(
            text,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )

        # Convert numpy array to Python list (for JSON serialization)
        return embedding.tolist()
    
    def get_embeddings(
        self,
        texts: List[str],
        show_progress: bool = True,
        batch_size: int = 256,
    ) -> List[List[float]]:
        """
        Convert multiple texts into embeddings efficiently (batched processing).

        Args:
            texts: List of texts to embed
            show_progress: Whether to show a progress bar
            batch_size: Texts encoded per forward pass. Larger batches raise
                throughput up to the point where memory becomes the constraint;
                256 is a reasonable CPU default.

        Returns:
            List of embedding vectors, one per input text

        This is much faster than calling get_embedding() in a loop because:
        1. The model can process multiple texts simultaneously (batching)
        2. GPU acceleration is utilized if available

        Vectors are L2-normalized so that cosine similarity and Euclidean
        distance rank identically, which keeps distance scores comparable
        across collections and makes a relevance threshold meaningful.
        """
        if not texts:
            return []

        # Batch encoding is far faster than one-by-one
        embeddings = self.model.encode(
            texts,
            convert_to_numpy=True,
            show_progress_bar=show_progress,
            batch_size=batch_size,
            normalize_embeddings=True,
        )

        # Convert to list of lists
        return embeddings.tolist()
    
    def get_embedding_dimension(self) -> int:
        """
        Get the dimension of the embedding vectors.
        
        Returns:
            The number of dimensions (384 for all-MiniLM-L6-v2)

        sentence-transformers 5.x renamed this method; fall back to the old name
        so the service works on either major version.
        """
        getter = getattr(self.model, "get_embedding_dimension", None)
        if getter is None:
            getter = self.model.get_sentence_embedding_dimension
        return getter()


# Quick test function (run this file directly to test)
if __name__ == "__main__":
    print("Testing Embedding Service...")
    
    service = EmbeddingService()
    
    # Test single embedding
    test_text = "Remote code execution vulnerability in Apache Struts"
    embedding = service.get_embedding(test_text)
    print(f"\n[OK] Single embedding test:")
    print(f"Input: {test_text}")
    print(f"Output dimension: {len(embedding)}")
    print(f"First 5 values: {embedding[:5]}")
    
    # Test batch embedding
    test_texts = [
        "SQL injection in web application",
        "Authentication bypass vulnerability",
        "Cross-site scripting (XSS) attack"
    ]
    embeddings = service.get_embeddings(test_texts)
    print(f"\n[OK] Batch embedding test:")
    print(f"Processed {len(embeddings)} texts")
    print(f"Each has {len(embeddings[0])} dimensions")
    
    print("\n[OK] All tests passed!")

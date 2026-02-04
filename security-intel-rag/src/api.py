"""
REST API for Security Intelligence RAG System

This provides HTTP endpoints so the RAG system can be used by:
- Web applications
- Other microservices  
- Integration with SIEM/SOAR platforms
- Automated security workflows

Endpoints:
- POST /query - Main query endpoint
- GET /health - Health check
- GET /stats - Database statistics
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
import uvicorn

from query import SecurityRAG


# Pydantic models for request/response validation
class QueryRequest(BaseModel):
    """
    Request model for security queries.
    """
    question: str = Field(..., description="The security question to answer", min_length=5)
    n_results: int = Field(5, description="Number of documents to retrieve", ge=1, le=20)
    query_type: str = Field("general", description="Type of query (general, cve, threat, summary, mitigation)")
    severity_filter: Optional[str] = Field(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)")
    cve_only: bool = Field(False, description="Only retrieve CVE documents")
    threat_only: bool = Field(False, description="Only retrieve threat intelligence")
    return_context: bool = Field(False, description="Include retrieved documents in response")
    
    class Config:
        json_schema_extra = {
            "example": {
                "question": "What vulnerabilities affect VMware vSphere?",
                "n_results": 5,
                "query_type": "cve",
                "severity_filter": "CRITICAL"
            }
        }


class Source(BaseModel):
    """Model for source citation."""
    type: str
    id: Optional[str]
    title: Optional[str]
    severity: Optional[str]
    threat_actor: Optional[str]


class QueryResponse(BaseModel):
    """
    Response model for security queries.
    """
    answer: str = Field(..., description="The generated answer")
    sources: List[Source] = Field(..., description="List of sources used")
    n_sources: int = Field(..., description="Number of sources")
    context: Optional[str] = Field(None, description="Retrieved context (if requested)")
    error: Optional[str] = Field(None, description="Error message if any")


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    message: str


class StatsResponse(BaseModel):
    """Database statistics response."""
    total_documents: int
    collection_name: str


# Initialize FastAPI app
app = FastAPI(
    title="Security Intelligence RAG API",
    description="AI-powered security intelligence platform using RAG architecture",
    version="1.0.0",
    docs_url="/docs",  # Swagger UI at /docs
    redoc_url="/redoc"  # ReDoc at /redoc
)

# Enable CORS (for web applications)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize RAG system (done once at startup)
rag_system = None


@app.on_event("startup")
async def startup_event():
    """
    Initialize the RAG system when the API starts.
    """
    global rag_system
    print("Initializing Security RAG System...")
    try:
        rag_system = SecurityRAG()
        print("✓ RAG System initialized successfully")
    except Exception as e:
        print(f"❌ Error initializing RAG system: {e}")
        print("The API will run but queries will fail.")
        print("Make sure to:")
        print("  1. Run 'python src/ingest.py' first")
        print("  2. Set ANTHROPIC_API_KEY in .env")


@app.get("/", response_model=HealthResponse)
async def root():
    """
    Root endpoint - basic info.
    """
    return {
        "status": "online",
        "message": "Security Intelligence RAG API - Visit /docs for API documentation"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Health check endpoint.
    
    Returns:
        Status of the system and database connection
    """
    if rag_system is None:
        raise HTTPException(
            status_code=503,
            detail="RAG system not initialized. Check server logs."
        )
    
    try:
        # Test database connection
        count = rag_system.collection.count()
        return {
            "status": "healthy",
            "message": f"System operational. Database has {count} documents."
        }
    except Exception as e:
        raise HTTPException(
            status_code=503,
            detail=f"Database error: {str(e)}"
        )


@app.get("/stats", response_model=StatsResponse)
async def get_stats():
    """
    Get database statistics.
    
    Returns:
        Number of documents and collection info
    """
    if rag_system is None:
        raise HTTPException(
            status_code=503,
            detail="RAG system not initialized"
        )
    
    try:
        count = rag_system.collection.count()
        return {
            "total_documents": count,
            "collection_name": rag_system.collection.name
        }
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error getting stats: {str(e)}"
        )


@app.post("/query", response_model=QueryResponse)
async def query_security_intel(request: QueryRequest):
    """
    Main query endpoint - ask security questions and get AI-powered answers.
    
    This endpoint:
    1. Retrieves relevant security documents from the vector database
    2. Uses Claude AI to generate informed answers
    3. Returns the answer with source citations
    
    Args:
        request: Query request with question and optional filters
        
    Returns:
        QueryResponse with answer, sources, and optional context
        
    Example:
        ```
        POST /query
        {
            "question": "What are the critical VMware vulnerabilities?",
            "severity_filter": "CRITICAL",
            "cve_only": true
        }
        ```
    """
    if rag_system is None:
        raise HTTPException(
            status_code=503,
            detail="RAG system not initialized. Server may still be starting up."
        )
    
    try:
        # Build filter metadata
        filter_metadata = {}
        
        if request.severity_filter:
            filter_metadata["severity"] = request.severity_filter
        
        if request.cve_only:
            filter_metadata["type"] = "cve"
        elif request.threat_only:
            filter_metadata["type"] = "threat_intel"
        
        # Execute query
        result = rag_system.query(
            question=request.question,
            n_results=request.n_results,
            query_type=request.query_type,
            filter_metadata=filter_metadata if filter_metadata else None,
            return_context=request.return_context
        )
        
        # Convert sources to proper models
        sources = [Source(**source) for source in result["sources"]]
        
        return QueryResponse(
            answer=result["answer"],
            sources=sources,
            n_sources=result["n_sources"],
            context=result.get("context"),
            error=result.get("error")
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error processing query: {str(e)}"
        )


# Run the API server
if __name__ == "__main__":
    print("=" * 70)
    print("Starting Security Intelligence RAG API")
    print("=" * 70)
    print("\nAPI will be available at:")
    print("  - Main API: http://localhost:8000")
    print("  - Swagger UI: http://localhost:8000/docs")
    print("  - ReDoc: http://localhost:8000/redoc")
    print("\nPress Ctrl+C to stop\n")
    
    # Run server
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )

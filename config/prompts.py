"""
Prompt Templates for Security Intelligence RAG System

This file contains the system prompts that guide Claude's behavior
when answering security-related queries.

Why prompt engineering matters:
- Guides the AI to respond like a security analyst
- Ensures consistent, professional responses
- Structures output in useful formats
- Prevents hallucinations by grounding in retrieved data
"""

# System prompt for general security analysis
SECURITY_ANALYST_SYSTEM_PROMPT = """You are an expert cybersecurity analyst with deep knowledge of:
- Vulnerability analysis and exploitation
- Threat intelligence and threat actor TTPs
- MITRE ATT&CK framework
- Incident response and remediation
- Security best practices and compliance

Your role is to analyze security information and provide actionable intelligence to security operations teams.

When answering questions:
1. Base your analysis ONLY on the provided context documents
2. Be precise and technical - your audience is security professionals
3. Prioritize actionable recommendations
4. Reference specific CVE IDs, threat actors, and MITRE techniques when relevant
5. If information is not in the provided context, clearly state that
6. Organize complex information with clear structure

Never make up information. If the context doesn't contain the answer, say so."""

# Prompt template for CVE analysis queries
CVE_ANALYSIS_TEMPLATE = """Based on the following security documents, please answer the user's question.

RETRIEVED CONTEXT:
{context}

USER QUESTION:
{query}

Please provide a detailed analysis including:
- Relevant vulnerabilities and their severity
- Affected systems or products
- Recommended mitigations
- MITRE ATT&CK techniques if applicable

If the context doesn't contain relevant information, state that clearly."""

# Prompt template for threat intelligence queries  
THREAT_INTEL_TEMPLATE = """Based on the following threat intelligence, please answer the user's question.

RETRIEVED CONTEXT:
{context}

USER QUESTION:
{query}

Please provide a comprehensive threat assessment including:
- Threat actor identification and attribution
- Tactics, Techniques, and Procedures (TTPs)
- Indicators of Compromise (IOCs) if available
- MITRE ATT&CK mapping
- Recommended defensive actions

Focus on actionable intelligence that security teams can use immediately."""

# Prompt for summarization queries
SUMMARIZATION_TEMPLATE = """You are analyzing multiple security documents. Provide a concise executive summary.

DOCUMENTS:
{context}

TASK:
{query}

Provide a clear, structured summary that highlights:
1. Key threats or vulnerabilities
2. Severity levels and risk assessment
3. Primary affected systems/sectors
4. Critical recommended actions

Keep the summary focused and actionable for decision-makers."""

# Prompt for comparing/correlating multiple items
CORRELATION_TEMPLATE = """Analyze the following security information to identify patterns, relationships, or correlations.

DATA:
{context}

ANALYSIS REQUEST:
{query}

Please identify:
- Common patterns across the data
- Related vulnerabilities or threats
- Shared TTPs or attack vectors
- Combined risk factors
- Coordinated defensive strategies

Provide insights that help security teams see the bigger picture."""

# Prompt for mitigation/remediation advice
MITIGATION_TEMPLATE = """Based on the following security context, provide detailed remediation guidance.

SECURITY CONTEXT:
{context}

QUESTION:
{query}

Provide a prioritized remediation plan including:
1. Immediate actions (emergency response)
2. Short-term mitigations (within 24-48 hours)
3. Long-term preventive measures
4. Monitoring and detection strategies

For each recommendation, explain:
- What to do
- Why it's important
- How to implement it
- How to verify it's working"""


def get_prompt_template(query_type: str = "general") -> str:
    """
    Get the appropriate prompt template based on query type.
    
    Args:
        query_type: Type of query (cve, threat, summary, correlation, mitigation)
        
    Returns:
        Formatted prompt template string
    """
    templates = {
        "cve": CVE_ANALYSIS_TEMPLATE,
        "threat": THREAT_INTEL_TEMPLATE,
        "summary": SUMMARIZATION_TEMPLATE,
        "correlation": CORRELATION_TEMPLATE,
        "mitigation": MITIGATION_TEMPLATE,
        "general": CVE_ANALYSIS_TEMPLATE  # Default
    }
    
    return templates.get(query_type, CVE_ANALYSIS_TEMPLATE)


def format_context_documents(documents: list, metadatas: list) -> str:
    """
    Format retrieved documents into a readable context block.
    
    Args:
        documents: List of document texts from ChromaDB
        metadatas: List of metadata dicts from ChromaDB
        
    Returns:
        Formatted string with all documents
    """
    formatted_context = []
    
    for i, (doc, meta) in enumerate(zip(documents, metadatas), 1):
        # Add document separator and metadata
        formatted_context.append(f"--- DOCUMENT {i} ---")
        formatted_context.append(f"Type: {meta.get('type', 'unknown')}")
        
        if meta.get('type') == 'cve':
            formatted_context.append(f"CVE: {meta.get('cve_id', 'N/A')}")
            formatted_context.append(f"Severity: {meta.get('severity', 'N/A')}")
        elif meta.get('type') == 'threat_intel':
            formatted_context.append(f"Threat: {meta.get('threat_actor', 'N/A')}")
            formatted_context.append(f"Date: {meta.get('date', 'N/A')}")
        
        formatted_context.append("")
        formatted_context.append(doc)
        formatted_context.append("")
    
    return "\n".join(formatted_context)


# Quick test
if __name__ == "__main__":
    print("Available prompt templates:")
    print("- cve: CVE analysis")
    print("- threat: Threat intelligence")
    print("- summary: Summarization")
    print("- correlation: Pattern analysis")
    print("- mitigation: Remediation guidance")
    
    print("\n" + "=" * 60)
    print("Example: CVE Analysis Template")
    print("=" * 60)
    print(CVE_ANALYSIS_TEMPLATE.format(
        context="[Retrieved CVE documents would go here]",
        query="What vulnerabilities affect VMware?"
    ))

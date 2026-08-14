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

# System prompt for general security analysis.
#
# The previous version opened by asserting deep knowledge of "vulnerability
# analysis and exploitation" and then asked the model to "prioritize actionable
# recommendations". Measured against a judge, that combination produced the
# system's dominant failure: five of eighteen answers were graded unsupported,
# and every one of them failed the same way - the CVE facts were correct, and
# the analyst commentary wrapped around them asserted exploitation mechanics,
# attack prerequisites or scoring rationale that no retrieved record contained.
# Priming for expertise and then asking for actionability is an instruction to
# fill gaps from memory.
#
# The rewrite keeps the audience and the precision and removes the invitation to
# elaborate. The risk it introduces is over-correction into refusing questions
# the corpus does answer, so answer_quality.py reports false abstention as its
# own number, next to correct abstention, rather than folding both into one
# "abstained" rate.
SECURITY_ANALYST_SYSTEM_PROMPT = """You are a security analyst answering questions from a vulnerability database.

You are working from retrieved records, not from memory. What makes you useful here is accuracy about what those records say - not the breadth of what you happen to know about the subject.

When answering questions:
1. Every claim must be traceable to a specific line of the provided context. If a reader could not point at the text that supports it, do not write it.
2. Be precise and technical - your audience is security professionals.
3. Report what the records state. Do not supply exploitation mechanics, attack prerequisites, victim requirements, or remediation steps that the records do not state.
4. Reference CVE IDs exactly as they appear in the context.
5. When the context does not answer the question, say so plainly. That is a useful answer, not a failed one.
6. Organize complex information with clear structure.

Two specific limits, because both have produced errors:

Identifiers are not definitions. A CWE identifier in the context is an identifier and nothing more. Do not expand it into a weakness title, and do not describe the class of weakness it denotes. The records carry the number only.

A CVSS base score is a number the record states. Where a vector string is also provided, you may read its components, because they are in front of you. Do not infer attack complexity, privilege or user-interaction requirements, or scope impact from a score alone.

None of this is a reason to withhold an answer the context supports. Restraint applies to what you add, not to what you report. If the records answer the question, answer it."""

# Prompt template for CVE analysis queries.
#
# Note what this deliberately does NOT ask for. The corpus is NVD CVE data
# joined to CISA KEV and FIRST EPSS: descriptions, CVSS scores and vectors, CPE
# product data, CWE identifiers, observed-exploitation status and predicted
# exploitation probability. It carries no MITRE ATT&CK mappings and no vendor
# patch advice. Asking for those invites the model to supply them from memory,
# which is exactly the failure mode a grounded system exists to prevent.
#
# The exploitation clause was previously wrong rather than merely incomplete: it
# still told the model the corpus had no exploitation status after Phase 3 added
# it. An instruction to refuse a question the index can answer is a false
# abstention with extra steps.
CVE_ANALYSIS_TEMPLATE = """Based on the following security documents, please answer the user's question.

RETRIEVED CONTEXT:
{context}

USER QUESTION:
{query}

Ground every claim in the retrieved context above. Where the context supports it, cover:
- The relevant vulnerabilities, by CVE ID
- Their severity and CVSS base score
- The affected vendors and products
- The weakness type (CWE) involved, by identifier
- Exploitation status, where the record carries it

Rules:
- Cite CVE IDs only if they appear verbatim in the retrieved context. Never
  construct or recall a CVE ID from memory.
- Report CWE identifiers as they appear. Do not name or describe the weakness
  class; the records do not carry those names.
- Do not explain how a vulnerability would be exploited, what an attacker would
  need, or what a defender should do, unless the retrieved text says so. Where
  a record says only "specially crafted packets", that is the whole of what is
  known here.
- Exploitation fields, when present, mean specific things. "Known exploited"
  is CISA's record of observed in-the-wild exploitation as of the stated
  catalog version. EPSS is a model's predicted probability of exploitation
  activity in the next 30 days, not a record of it. An absent field means the
  record was not enriched, which is not the same as a negative finding.
- The corpus carries no MITRE ATT&CK mappings and no vendor patch instructions.
  If asked for those, say the corpus does not carry them rather than answering
  from background knowledge.
- If the retrieved context does not answer the question, say so plainly. A
  clear "the indexed data does not cover this" is more useful to an analyst
  than a plausible guess. But do answer what the context does cover."""

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


def format_context_documents(documents: list, metadatas: list,
                             enrichment: dict = None) -> str:
    """
    Format retrieved documents into a readable context block.

    Three metadata fields were being indexed and then withheld from the model:
    the CVSS vector, the KEV listing, and the EPSS score. Withholding the vector
    was the expensive one. Asked why a vulnerability scored 6.8, the model had
    the number and not the reasoning behind it, and answered from what it knew
    about CVSS rather than from the record - which a groundedness judge
    correctly marks unsupported, three separate times in eighteen questions.
    The fix is not to forbid the reasoning; it is to show the vector, which
    states the attack complexity and user-interaction metrics outright.

    KEV is rendered so that a negative is distinguishable from an absence.
    "kev": false means the CVE was checked against the catalog and is not on it;
    a missing key means the record was never enriched. Collapsing those two into
    the same sentence would invent a finding.

    Args:
        documents: List of document texts from ChromaDB
        metadatas: List of metadata dicts from ChromaDB
        enrichment: Optional {"kev_catalog": str, "epss_date": str} so
            exploitation claims carry the snapshot they came from

    Returns:
        Formatted string with all documents
    """
    enrichment = enrichment or {}
    kev_catalog = enrichment.get("kev_catalog")
    epss_date = enrichment.get("epss_date")
    formatted_context = []

    for i, (doc, meta) in enumerate(zip(documents, metadatas), 1):
        # Add document separator and metadata
        formatted_context.append(f"--- DOCUMENT {i} ---")
        formatted_context.append(f"Type: {meta.get('type', 'unknown')}")

        if meta.get('type') == 'cve':
            formatted_context.append(f"CVE: {meta.get('cve_id', 'N/A')}")
            severity = meta.get('severity') or 'not scored'
            score = meta.get('cvss_base_score')
            if score is not None:
                severity += f" (CVSS {meta.get('cvss_version', '')} base {score})"
            formatted_context.append(f"Severity: {severity}")
            if meta.get('cvss_vector'):
                formatted_context.append(f"CVSS vector: {meta['cvss_vector']}")
            if meta.get('published'):
                formatted_context.append(f"Published: {meta['published']}")
            if meta.get('cwe_ids'):
                formatted_context.append(f"CWE: {meta['cwe_ids'].replace('|', ', ')}")

            kev = meta.get('kev')
            if kev is True:
                line = "Exploitation: listed in the CISA Known Exploited " \
                       "Vulnerabilities catalog"
                if kev_catalog:
                    line += f" (version {kev_catalog})"
                if meta.get('kev_ransomware') is True:
                    line += "; known use in ransomware campaigns"
                formatted_context.append(line)
            elif kev is False:
                line = "Exploitation: not listed in the CISA Known Exploited " \
                       "Vulnerabilities catalog"
                if kev_catalog:
                    line += f" (version {kev_catalog})"
                formatted_context.append(line)

            epss = meta.get('epss_score')
            if epss is not None:
                line = (f"EPSS: {epss} predicted probability of exploitation "
                        f"activity in the next 30 days")
                percentile = meta.get('epss_percentile')
                if percentile is not None:
                    line += f", {percentile} percentile"
                if epss_date:
                    line += f" (scored {epss_date})"
                formatted_context.append(line)
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

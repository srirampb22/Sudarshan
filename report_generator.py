#!/usr/bin/env python3
"""
Sudarshan :: Report Narrative Generator (Ollama)   (report_generator.py)
Phase 3 of the Sudarshan -> AI report pipeline.

WHAT THIS IS
------------
Takes the session.json built by session_builder.py (Phase 2) and generates
the narrative sections of a pentest report using a LOCAL Ollama model.
Optionally, it can retrieve matching reference context from a local ChromaDB
vector store before prompting the model, giving the report writer both the
current target facts and a reusable local context library.

GROUNDING, NOT GENERATING FACTS
--------------------------------
The model NEVER produces the facts themselves - the CVE list, exploit
list, port/service table etc. in the final report come directly from
session.json, deterministically, every time. The model only writes the
prose *around* those facts (executive summary, technical narrative,
recommendations). After each generation, the output is scanned for CVE
IDs and any that don't appear in session.json are flagged as a possible
hallucination rather than silently trusted - this is the "grounded in
real facts, not guessed" box in the pipeline diagram, done in software,
not by hoping the model behaves.

REQUIREMENTS
------------
  - Ollama installed and running:  https://ollama.com
  - Default report model pulled locally:  ollama pull qwen2.5:7b-instruct
  - Default RAG embedding model pulled locally:  ollama pull nomic-embed-text
  - pip install requests
  - Optional RAG support: pip install chromadb

USAGE
-----
  # Full report, default model:
  python3 report_generator.py --session session.json --out report.md

  # Pick a model, lower/raise creativity:
  python3 report_generator.py --session session.json --out report.md \\
      --model mistral --temperature 0.2

  # Just see the prompts without calling the model (prompt-engineering loop):
  python3 report_generator.py --session session.json --dry-run

  # Only regenerate one section while iterating (fast feedback loop):
  python3 report_generator.py --session session.json --out report.md \\
      --sections executive_summary

CHANGELOG
---------
v1 (phase 3) - initial Ollama /api/chat integration. Three narrative
               sections (executive summary, technical findings,
               recommendations), deterministic facts table assembled
               separately, post-generation CVE grounding check,
               --dry-run mode for prompt iteration without a model call.
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import datetime
import hashlib

import sudarshan_config as config

try:
    import requests
except ImportError:
    requests = None

try:
    import chromadb
except ImportError:
    chromadb = None

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}")

OLLAMA_DEFAULT_URL = config.OLLAMA_DEFAULT_URL
DEFAULT_MODEL = config.REPORT_MODEL
DEFAULT_EMBED_MODEL = config.EMBED_MODEL
DEFAULT_TEMPERATURE = 0.3
MAX_FACTS_FINDINGS = 25  # cap how many service findings go into the prompt context
DEFAULT_VECTORSTORE_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), config.VECTORSTORE_DIR
)
DEFAULT_COLLECTION_NAME = config.VECTORSTORE_COLLECTION
DEFAULT_RAG_K = 4

SECTION_ORDER = ["executive_summary", "technical_findings", "recommendations"]

SYSTEM_PROMPT = textwrap.dedent("""\
    You are a professional penetration testing report writer helping a
    security analyst turn raw scan facts into report prose.

    Hard rules, no exceptions:
    - Use ONLY the facts given to you in the user's message. Never invent,
      assume, or infer a CVE ID, exploit name, hostname, port, service,
      version, or finding that is not explicitly present in those facts.
    - Never introduce a vulnerability class (e.g. SQL Injection, XSS,
      RCE, buffer overflow) for a service unless a CVE description or
      exploit title given to you explicitly names or clearly implies it.
      A service having no CVEs/exploits listed means you say exactly
      that - it is NOT an invitation to guess a plausible-sounding
      vulnerability for that kind of service.
    - Never discuss a port or service that is not explicitly listed in
      the facts, even if it is a common/expected port for that type of
      target (e.g. do not mention port 443, 3389, 8080, or any other
      port not given to you, even as a generic example).
    - If the facts are insufficient to support a claim, say so plainly
      instead of guessing or filling the gap with generic security advice
      dressed up as a specific finding.
    - Refer to CVE IDs and exploit titles exactly as given - do not
      paraphrase or renumber them.
    - Write clear, professional prose suitable for a client-facing
      security assessment. Do not include markdown headers (#, ##) in
      your response - the surrounding report template supplies those.
      Plain paragraphs and bullet lists only.
    """)


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# ----------------------------------------------------------------------------
# Facts context (deterministic - this text is what "grounds" every prompt)
# ----------------------------------------------------------------------------


def build_facts_context(session, max_findings=MAX_FACTS_FINDINGS):
    lines = []
    lines.append(f"Target: {session.get('target', 'unknown')}")
    lines.append(f"Engagement name: {session.get('friendly_name', 'unknown')}")

    hosts = session.get("host_discovery", {}).get("hosts", [])
    if hosts:
        up = [h["host"] for h in hosts if h.get("up")]
        lines.append(f"Hosts confirmed up: {', '.join(up) if up else '(none confirmed up)'}")

    findings = session.get("cve_exploit_findings", [])
    total_cves = sum(len(f.get("cves", [])) for f in findings)
    total_exploits = sum(len(f.get("exploits", [])) for f in findings)
    lines.append(f"\nServices discovered: {len(findings)}")
    lines.append(f"Total CVEs identified across all services: {total_cves}")
    lines.append(f"Total exploits identified across all services: {total_exploits}")
    shown = findings[:max_findings]
    for f in shown:
        lines.append(f"\n- {f['port']}/{f['proto']} {f['service']} - {f['version_raw']}")
        if f.get("cves"):
            for cve in f["cves"]:
                sev = cve.get("severity") or "UNKNOWN"
                score = cve.get("cvss_score")
                score_str = f"{score}" if score is not None else "n/a"
                lines.append(f"    CVE: {cve['id']} (CVSS {score_str}, {sev}) - "
                              f"{(cve.get('description') or '').strip()[:200]}")
        else:
            lines.append("    CVEs: none found")
        if f.get("exploits"):
            for ex in f["exploits"]:
                lines.append(f"    Exploit: {ex.get('title')} (EDB-ID {ex.get('edb_id')}, "
                              f"type={ex.get('type')}, platform={ex.get('platform')})")
        else:
            lines.append("    Exploits: none found")

    if len(findings) > max_findings:
        lines.append(f"\n... {len(findings) - max_findings} additional service(s) not shown "
                      f"in this context (raise --max-findings to include more).")

    vuln = session.get("vulnerability_scan", {})
    unattributed_cves = vuln.get("cves_referenced_in_scan", [])
    if unattributed_cves:
        # Deliberately NOT listing the individual CVE IDs here. These come
        # from a target-wide nmap NSE vulners sweep with no per-port
        # attribution in session.json. Handing a model a raw pile of real
        # CVE IDs with nowhere to put them predictably causes it to invent
        # a plausible-sounding service/port to attach them to (observed:
        # a nonexistent 'port 443' fabricated specifically to host this
        # list). A count is enough context; the actual IDs stay out of the
        # prompt so they can't be mis-attributed to a specific finding.
        lines.append(
            f"\nnmap NSE vulnerability scripts additionally flagged "
            f"{len(unattributed_cves)} CVE reference(s) across the target as a "
            f"whole that are NOT tied to any specific port/service in this scan. "
            f"You may mention this count in general terms (e.g. in an executive "
            f"summary) but must NEVER list, quote, or attribute any of these "
            f"individual CVE IDs to a specific port or service - their per-port "
            f"origin is unknown."
        )
    if vuln.get("vulnerable_flags"):
        lines.append(f"nmap NSE flagged {vuln['vulnerable_flags']} VULNERABLE result(s).")

    subs = session.get("subdomains", [])
    if subs:
        lines.append(f"\nSubdomains found ({len(subs)}): {', '.join(subs[:20])}"
                      f"{' ...' if len(subs) > 20 else ''}")

    live = session.get("live_hosts", [])
    if live:
        lines.append(f"\nLive web hosts ({len(live)}):")
        for h in live[:15]:
            lines.append(f"  - {h['url']} [{h.get('status_code')}] {h.get('title') or ''} "
                          f"tech={','.join(h.get('tech', []))}")

    paths = session.get("web_paths", [])
    if paths:
        lines.append(f"\nWeb paths discovered ({len(paths)}): "
                      f"{', '.join(p['path'] for p in paths[:20])}"
                      f"{' ...' if len(paths) > 20 else ''}")

    return "\n".join(lines)


def split_findings_by_evidence(session):
    """Split findings into those with at least one CVE/exploit ('evidence')
    and those with none. This is the core of the anti-hallucination fix:
    services with no evidence are never sent to the model for narrative
    generation at all - the model literally cannot invent a vulnerability
    for something it's never shown. Their 'nothing found' line is instead
    rendered deterministically in code, guaranteed accurate every time."""
    with_evidence, without_evidence = [], []
    for f in session.get("cve_exploit_findings", []):
        if f.get("cves") or f.get("exploits"):
            with_evidence.append(f)
        else:
            without_evidence.append(f)
    return with_evidence, without_evidence


def render_no_evidence_list(without_evidence):
    """Deterministic (not model-generated) list of services with no CVEs
    or exploits found - always 100% accurate since it's built directly
    from session.json, never written by the model."""
    if not without_evidence:
        return ""
    lines = [
        "\nThe following additional services were identified but had no "
        "CVEs or exploit matches in this scan:",
        "",
    ]
    for f in without_evidence:
        lines.append(f"- {f['port']}/{f['proto']} {f['service']} - {f['version_raw']}: "
                      f"nothing identified for this service in this scan.")
    return "\n".join(lines)


def build_rag_query(session, max_findings=12):
    """Compact retrieval query for RAG embedding - deliberately much shorter
    than the full facts context. Embedding models have their own (often
    small) context window, and on a target with many discovered services
    the full facts block can exceed it, causing the embeddings call to
    fail outright (HTTP 500 'input length exceeds the context length').
    Only service names/versions are needed to retrieve relevant background
    context - CVE descriptions aren't needed for that matching."""
    parts = [f"Target: {session.get('target', 'unknown')}"]
    findings = session.get("cve_exploit_findings", [])[:max_findings]
    for f in findings:
        parts.append(f"{f.get('service', '?')} {f.get('version_raw', '')}".strip())
    return "; ".join(parts)[:1500]


def known_cve_ids(session):
    """Every CVE ID that actually exists somewhere in session.json - the
    allow-list used to catch hallucinated CVEs in generated text."""
    known = set()
    for f in session.get("cve_exploit_findings", []):
        for cve in f.get("cves", []):
            known.add(cve["id"])
    for cve_id in session.get("vulnerability_scan", {}).get("cves_referenced_in_scan", []):
        known.add(cve_id)
    return known


def build_described_port_mentions(session):
    """Port-like numbers that appear inside the REAL CVE descriptions or
    exploit titles in session.json - e.g. CVE-2011-2523's real NVD text
    says 'opens a shell on port 6200/tcp'. These are legitimate facts the
    model is allowed to repeat, not fabrications, even though 6200 was
    never itself a scanned port."""
    text = build_vuln_class_evidence(session)  # already concatenates all descriptions+titles, lowercased
    found = set()
    for m in PORT_MENTION_PATTERN.finditer(text):
        for g in m.groups():
            if g:
                found.add(g)
    return found


def known_ports(session):
    """Every port number that actually appears in session.json findings -
    the allow-list used to catch fabricated ports/services in generated
    text (e.g. a model inventing 'Port 443 (HTTPS)' or 'Port 3389 (RDP)'
    that was never in the scan)."""
    return {str(f["port"]) for f in session.get("cve_exploit_findings", []) if "port" in f}


PORT_MENTION_PATTERN = re.compile(
    r"\b(?:port|service)\s*:?\s*(\d{1,5})\b"       # "port 443", "Service: 443"
    r"|\b(\d{1,5})\s*/\s*(?:tcp|udp)\b"             # "6677/tcp"
    r"|\b(?:tcp|udp)\s*/\s*(\d{1,5})\b",            # "TCP/6671"
    re.IGNORECASE,
)


def check_port_grounding(text, known_ports_set, described_ports=None):
    """Return sorted list of port numbers mentioned in `text` in any of
    several common phrasings ('port N', 'Service: N', 'N/tcp', 'TCP/N')
    that do NOT appear anywhere in session.json's scanned ports AND are
    not legitimately part of a real CVE description (e.g. CVE-2011-2523's
    real description says 'opens a shell on port 6200/tcp' - 6200 was
    never scanned, but it's a real fact from the real CVE text, not a
    fabrication, so it must not be flagged)."""
    if not known_ports_set:
        return []
    described_ports = described_ports or set()
    mentioned = set()
    for m in PORT_MENTION_PATTERN.finditer(text):
        for g in m.groups():
            if g:
                mentioned.add(g)
    return sorted(mentioned - known_ports_set - described_ports, key=int)


def check_grounding(text, known_cves):
    """Return sorted list of CVE IDs mentioned in `text` that are NOT in
    known_cves - i.e. likely hallucinated."""
    mentioned = set(CVE_PATTERN.findall(text))
    return sorted(mentioned - known_cves)


VULN_CLASS_KEYWORDS = [
    "sql injection", "cross-site scripting", "xss", "remote code execution",
    "buffer overflow", "denial of service", "privilege escalation",
    "authentication bypass", "path traversal", "cross-site request forgery",
    "csrf", "command injection", "arbitrary code execution", "backdoor",
    "use-after-free", "null pointer dereference", "race condition",
]

# Real CVE descriptions rarely use the exact category phrase a model reaches
# for - e.g. NVD says "execute arbitrary code", not "remote code execution",
# even though they mean the same thing. Without this, check_vuln_class_
# grounding() false-positives on accurate paraphrases (observed: flagging
# "remote code execution" as unsupported when the real description said
# "allow ... remote attackers to execute arbitrary code" - same fact,
# different wording). Each keyword's aliases are phrases that, if present
# in the evidence, count as that keyword being supported too.
VULN_CLASS_ALIASES = {
    "remote code execution": ["execute arbitrary code", "arbitrary code execution",
                                "code execution", "run arbitrary code"],
    "privilege escalation": ["gain privileges", "elevate privileges", "escalate privileges",
                               "gain root", "as root", "unauthorized privileges"],
    "denial of service": ["cause a denial of service", "dos ", "crash the",
                            "service to crash", "server crash"],
    "authentication bypass": ["bypass authentication", "bypass security restrictions",
                                "without proper authentication", "without authentication"],
    "backdoor": ["contains a backdoor", "opens a shell"],
}


def build_vuln_class_evidence(session):
    """Lowercase concatenation of every real CVE description and exploit
    title in session.json - the ground truth used to check whether a
    vulnerability-class claim (SQL Injection, XSS, RCE, etc.) in generated
    text is actually backed by something, or just asserted. This catches a
    failure mode check_grounding()/check_port_grounding() can't: the model
    avoiding a fake CVE ID or port, but still asserting a category of
    vulnerability nothing in the real data supports (e.g. claiming 'Apache
    servers are vulnerable to SQL injection' when no CVE anywhere mentions
    SQL injection)."""
    parts = []
    for f in session.get("cve_exploit_findings", []):
        for cve in f.get("cves", []):
            parts.append(cve.get("description", "") or "")
        for ex in f.get("exploits", []):
            parts.append(ex.get("title", "") or "")
    return " ".join(parts).lower()


def check_vuln_class_grounding(text, evidence_text):
    """Return vulnerability-class keywords mentioned in `text` that don't
    appear anywhere in the real CVE descriptions/exploit titles - checking
    both the literal keyword and its known paraphrase aliases before
    flagging, to avoid penalizing an accurate description written in
    different words than NVD's."""
    if not evidence_text:
        return []
    text_lower = text.lower()
    flagged = []
    for kw in VULN_CLASS_KEYWORDS:
        if kw not in text_lower:
            continue
        if kw in evidence_text:
            continue
        aliases = VULN_CLASS_ALIASES.get(kw, [])
        if any(alias in evidence_text for alias in aliases):
            continue
        flagged.append(kw)
    return flagged


# ----------------------------------------------------------------------------
# Local RAG context store (optional)
# ----------------------------------------------------------------------------


def get_rag_collection(vectorstore_path=DEFAULT_VECTORSTORE_PATH,
                       collection_name=DEFAULT_COLLECTION_NAME):
    if chromadb is None:
        raise RuntimeError("'chromadb' library not installed. Install with: pip install chromadb")
    os.makedirs(vectorstore_path, exist_ok=True)
    client = chromadb.PersistentClient(path=vectorstore_path)
    return client.get_or_create_collection(name=collection_name)


def embed_text(text, model=DEFAULT_EMBED_MODEL, url=OLLAMA_DEFAULT_URL, timeout=120):
    if requests is None:
        raise RuntimeError("'requests' library not installed. Install with: pip install requests")
    payload = {"model": model, "prompt": text}
    try:
        resp = requests.post(f"{url}/api/embeddings", json=payload, timeout=timeout)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Could not reach Ollama at {url}. Is it running? Start it with: ollama serve"
        )
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Ollama embedding request timed out after {timeout}s (model: {model}).")
    if resp.status_code == 404:
        raise RuntimeError(f"Embedding model '{model}' not found. Pull it with: ollama pull {model}")
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama embeddings returned HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return data.get("embedding")


def add_rag_context(text, metadata=None, doc_id=None, vectorstore_path=DEFAULT_VECTORSTORE_PATH,
                    collection_name=DEFAULT_COLLECTION_NAME, embed_model=DEFAULT_EMBED_MODEL,
                    url=OLLAMA_DEFAULT_URL):
    collection = get_rag_collection(vectorstore_path, collection_name)
    doc_id = doc_id or f"ctx_{collection.count() + 1:04d}"
    embedding = embed_text(text, model=embed_model, url=url)
    collection.upsert(
        ids=[doc_id],
        embeddings=[embedding],
        documents=[text],
        metadatas=[metadata or {"source": "user_added"}],
    )
    return doc_id


def chunk_text(text, max_chars=1800, overlap_chars=250):
    cleaned = re.sub(r"\n{3,}", "\n\n", text.strip())
    if not cleaned:
        return []

    chunks = []
    start = 0
    while start < len(cleaned):
        end = min(start + max_chars, len(cleaned))
        chunk = cleaned[start:end].strip()
        if chunk:
            chunks.append(chunk)
        if end == len(cleaned):
            break
        start = max(0, end - overlap_chars)
    return chunks


def read_context_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            raise RuntimeError("PDF ingestion needs pypdf. Install with: pip install pypdf")
        reader = PdfReader(path)
        return "\n\n".join((page.extract_text() or "") for page in reader.pages)

    if ext == ".docx":
        try:
            import docx
        except ImportError:
            raise RuntimeError("DOCX ingestion needs python-docx. Install with: pip install python-docx")
        document = docx.Document(path)
        return "\n".join(p.text for p in document.paragraphs if p.text.strip())

    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def ingest_context_file(path, source_label=None, vectorstore_path=DEFAULT_VECTORSTORE_PATH,
                        collection_name=DEFAULT_COLLECTION_NAME,
                        embed_model=DEFAULT_EMBED_MODEL, url=OLLAMA_DEFAULT_URL,
                        max_chars=1800, overlap_chars=250):
    if not os.path.isfile(path):
        raise FileNotFoundError(f"No such context file: {path}")

    text = read_context_file(path)
    chunks = chunk_text(text, max_chars=max_chars, overlap_chars=overlap_chars)
    if not chunks:
        return {"path": path, "chunks": 0, "ids": []}

    source = source_label or os.path.basename(path)
    digest = hashlib.sha1(os.path.abspath(path).encode("utf-8")).hexdigest()[:10]
    ids = []
    for idx, chunk in enumerate(chunks, 1):
        doc_id = f"{digest}_{idx:04d}"
        metadata = {
            "source": source,
            "path": os.path.abspath(path),
            "chunk": idx,
            "chunks_total": len(chunks),
        }
        ids.append(add_rag_context(
            chunk,
            metadata=metadata,
            doc_id=doc_id,
            vectorstore_path=vectorstore_path,
            collection_name=collection_name,
            embed_model=embed_model,
            url=url,
        ))
    return {"path": path, "chunks": len(chunks), "ids": ids}


def retrieve_rag_context(query, k=DEFAULT_RAG_K, vectorstore_path=DEFAULT_VECTORSTORE_PATH,
                         collection_name=DEFAULT_COLLECTION_NAME,
                         embed_model=DEFAULT_EMBED_MODEL, url=OLLAMA_DEFAULT_URL):
    collection = get_rag_collection(vectorstore_path, collection_name)
    if collection.count() == 0:
        return []
    query_embedding = embed_text(query, model=embed_model, url=url)
    results = collection.query(query_embeddings=[query_embedding], n_results=k)
    docs = results.get("documents") or []
    return docs[0] if docs else []


def seed_example_context(vectorstore_path=DEFAULT_VECTORSTORE_PATH,
                         collection_name=DEFAULT_COLLECTION_NAME,
                         embed_model=DEFAULT_EMBED_MODEL, url=OLLAMA_DEFAULT_URL):
    collection = get_rag_collection(vectorstore_path, collection_name)
    if collection.count() > 0:
        return 0
    examples = [
        (
            "SQL Injection occurs when untrusted input is concatenated directly "
            "into a SQL query without parameterization, allowing an attacker to "
            "alter query logic, extract data, or bypass authentication.",
            {"source": "starter_context", "topic": "sql_injection"},
            "ctx_001",
        ),
        (
            "Cross-Site Scripting (XSS) allows an attacker to inject client-side "
            "scripts into web pages viewed by other users, potentially leading to "
            "session hijacking or credential theft.",
            {"source": "starter_context", "topic": "xss"},
            "ctx_002",
        ),
    ]
    for text, metadata, doc_id in examples:
        add_rag_context(text, metadata, doc_id, vectorstore_path, collection_name, embed_model, url)
    return len(examples)


def format_rag_context(chunks):
    if not chunks:
        return "No closely matching reference context was found."
    return "\n\n".join(f"- {chunk}" for chunk in chunks)


# ----------------------------------------------------------------------------
# Ollama client
# ----------------------------------------------------------------------------


def call_ollama(messages, model=DEFAULT_MODEL, url=OLLAMA_DEFAULT_URL,
                 temperature=DEFAULT_TEMPERATURE, timeout=300, max_tokens=900):
    if requests is None:
        raise RuntimeError("'requests' library not installed. Install with: pip install requests")

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": temperature, "num_predict": max_tokens},
    }
    try:
        resp = requests.post(f"{url}/api/chat", json=payload, timeout=timeout)
    except requests.exceptions.ConnectionError:
        raise RuntimeError(
            f"Could not reach Ollama at {url}. Is it running? Start it with: ollama serve"
        )
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Ollama request timed out after {timeout}s (model: {model}).")

    if resp.status_code == 404:
        raise RuntimeError(
            f"Model '{model}' not found on the Ollama server at {url}. "
            f"Pull it first with: ollama pull {model}"
        )
    if resp.status_code != 200:
        raise RuntimeError(f"Ollama returned HTTP {resp.status_code}: {resp.text[:300]}")

    data = resp.json()
    return data.get("message", {}).get("content", "").strip()


def list_ollama_models(url=OLLAMA_DEFAULT_URL):
    """Best-effort check of what's installed - used to give a clear error
    early instead of failing mid-report."""
    if requests is None:
        return None
    try:
        resp = requests.get(f"{url}/api/tags", timeout=10)
        if resp.status_code == 200:
            return [m["name"] for m in resp.json().get("models", [])]
    except requests.exceptions.RequestException:
        return None
    return None


# ----------------------------------------------------------------------------
# Section prompts
# ----------------------------------------------------------------------------


def with_reference_context(facts, rag_chunks=None):
    if not rag_chunks:
        return f"Facts from the assessment:\n\n{facts}"
    return (
        f"Facts from the assessment:\n\n{facts}\n\n"
        "Reference context retrieved from the local vector store. Use it only as "
        "supporting background; session facts remain authoritative:\n\n"
        f"{format_rag_context(rag_chunks)}"
    )


def prompt_executive_summary(facts, rag_chunks=None):
    context = with_reference_context(facts, rag_chunks)
    return (
        f"{context}\n\n"
        "Write a 150-250 word executive summary of this assessment for a "
        "non-technical stakeholder (e.g. a CTO or business owner). Cover: "
        "what was tested, the overall risk level implied by the facts above, "
        "and the single most important thing to fix first. Do not list every "
        "CVE individually - summarize the overall picture."
    )


def prompt_technical_findings(facts, rag_chunks=None):
    context = with_reference_context(facts, rag_chunks)
    return (
        f"{context}\n\n"
        "The facts above list ONLY the services that have at least one "
        "confirmed CVE or exploit match. This is the COMPLETE list - there "
        "is no other service to discuss. Write the technical findings "
        "narrative for a penetration test report, organized by service/port. "
        "For each service, explain in plain technical language what the "
        "listed CVE(s) mean and why they matter, using only the exact CVE "
        "IDs and descriptions given above - never write a CVE ID that is "
        "not printed above, and never mention a vulnerability class (SQL "
        "Injection, XSS, RCE, etc.) unless a given CVE description names it. "
        "Do not mention any port/service beyond what's listed above."
    )


def prompt_recommendations(facts, rag_chunks=None):
    context = with_reference_context(facts, rag_chunks)
    return (
        f"{context}\n\n"
        "The facts above list ONLY the services that have at least one "
        "confirmed CVE or exploit match - this is the COMPLETE list to "
        "base recommendations on. Write a prioritized remediation "
        "recommendations section. Base priority on CVSS severity where "
        "given. Group into 'Immediate', 'Short-term', and 'Long-term' if "
        "the facts support that many distinct priority levels - otherwise "
        "use fewer groups. Reference services/CVE IDs exactly as given "
        "above - never write a CVE ID that is not printed above. "
        "IMPORTANT - keep this concise: each distinct service/CVE should "
        "appear under ONE priority tier only, with ONE short recommendation "
        "(2-3 sentences max). Do not repeat the same CVE or service under "
        "multiple tiers, and do not write more than one recommendation per "
        "finding - you have limited space and must cover every service "
        "listed above at least briefly rather than writing at length about "
        "only the first one or two."
    )


def strip_duplicate_heading(text, title):
    """Models sometimes ignore the 'no markdown headers' system instruction
    and open their response with their own heading matching the section
    title (e.g. '### Executive Summary'), which then duplicates the real
    '## Executive Summary' heading the template already adds. Strip a
    leading markdown heading line if its text closely matches the title."""
    lines = text.split("\n", 1)
    if not lines:
        return text
    first_line = lines[0].strip()
    heading_match = re.match(r"^#{1,6}\s*(.+?)\s*#*$", first_line)
    if heading_match and heading_match.group(1).strip().lower() == title.strip().lower():
        remainder = lines[1] if len(lines) > 1 else ""
        return remainder.lstrip("\n")
    return text


# ----------------------------------------------------------------------------
# Per-finding generation (Technical Findings / Recommendations)
# ----------------------------------------------------------------------------
#
# Asking the model to write one long response covering every finding proved
# unreliable at 3B scale: given ~9 real findings, it would go deep on the
# first one or two it landed on and never reach the rest - including, in
# one real run, skipping the single highest-severity finding in the entire
# scan (CVE-2011-2523, CVSS 9.8, vsftpd backdoor) while writing at length
# about two lower/equal-severity ones. Re-prompting didn't fix it reliably.
#
# The fix mirrors the earlier evidence-only-facts fix: don't trust the
# model to remember to cover everything in one shot. Generate one short,
# focused response PER finding (a handful of small fast calls instead of
# one big one), and assemble the section deterministically in code. This
# guarantees every finding gets covered, since the loop is in Python, not
# in the model's attention.

def build_single_finding_facts(finding):
    """Facts block scoped to exactly one finding - used for per-finding
    generation so the model only ever sees what it needs for the item it's
    currently writing about."""
    lines = [f"{finding['port']}/{finding['proto']} {finding['service']} - {finding['version_raw']}"]
    for cve in finding.get("cves", []):
        parts = [cve["id"]]
        if cve.get("cvss_score") is not None:
            parts.append(f"CVSS {cve['cvss_score']} {cve.get('severity', '')}".strip())
        line = " - ".join(parts)
        desc = (cve.get("description") or "")[:250]
        if desc:
            line += f": {desc}"
        lines.append(line)
    for ex in finding.get("exploits", []):
        title = ex.get("title", "")
        if title:
            lines.append(f"Exploit available: {title}")
    return "\n".join(lines)


def finding_max_cvss(finding):
    scores = [c["cvss_score"] for c in finding.get("cves", []) if c.get("cvss_score") is not None]
    return max(scores) if scores else 0.0


def priority_tier(cvss):
    if cvss >= 9.0:
        return "Immediate"
    if cvss >= 7.0:
        return "Short-term"
    return "Long-term"


def _generate_and_check_finding_text(prompt_text, model, url, temperature, timeout,
                                       max_tokens, known_cves, known_ports_set,
                                       vuln_evidence, warnings, section_title, label,
                                       described_ports=None):
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": prompt_text},
    ]
    try:
        text = call_ollama(messages, model=model, url=url, temperature=temperature,
                            timeout=timeout, max_tokens=max_tokens)
    except RuntimeError as e:
        return f"[Generation failed: {e}]"

    for bad, msg_fmt in (
        (check_grounding(text, known_cves),
         "mentions CVE ID(s) not present in session.json (possible hallucination)"),
        (check_port_grounding(text, known_ports_set, described_ports),
         "references port(s) not found anywhere in session.json (likely fabricated)"),
        (check_vuln_class_grounding(text, vuln_evidence),
         "asserts vulnerability type(s) not supported by session.json (possible unsupported claim)"),
    ):
        if bad:
            warn = f"Section '{section_title}' ({label}) {msg_fmt}: {', '.join(bad)}"
            eprint(f"[!] {warn}")
            warnings.append(warn)
    return text


def generate_technical_findings_per_finding(with_evidence, model, url, temperature,
                                              timeout, max_tokens, rag_chunks,
                                              known_cves, known_ports_set, vuln_evidence,
                                              warnings, described_ports=None):
    blocks = []
    for finding in with_evidence:
        facts = build_single_finding_facts(finding)
        context = with_reference_context(facts, rag_chunks)
        prompt = (
            f"{context}\n\n"
            "Write a short technical explanation (3-5 sentences) of this ONE "
            "finding for a penetration test report - what the listed CVE(s) "
            "mean and why they matter, using only the exact facts given above. "
            "Never mention any other port, service, or CVE ID, and never "
            "assert a vulnerability class not named in the description above. "
            "Do not name a specific product/vendor variant (e.g. 'UltraVNC', "
            "'TightVNC', 'RealVNC') UNLESS that exact name is already present "
            "in the version string or CVE description given above - if a CVE "
            "description names a specific implementation, you may repeat that "
            "since it's a real fact from the CVE record itself. Only avoid "
            "guessing a variant that appears nowhere in the facts above. "
            "Do not include a markdown heading - plain prose only."
        )
        label = f"{finding['port']}/{finding['proto']} {finding['service']}"
        print(f"[*] Generating: Technical Findings - {label}...")
        text = _generate_and_check_finding_text(
            prompt, model, url, temperature, timeout, max_tokens,
            known_cves, known_ports_set, vuln_evidence, warnings,
            "Technical Findings", label, described_ports,
        )

        # Surface any low-confidence NVD match note (from cve_lookup.py)
        # directly in the report - previously this only lived in
        # session.json, invisible unless someone went looking for it. This
        # is added deterministically, never by the model, so it can't be
        # dropped, altered, or missed.
        note_block = ""
        if finding.get("nvd_query_precision_note"):
            note_block = f"\n\n> ⚠️ {finding['nvd_query_precision_note']}"

        header = f"### {finding['port']}/{finding['proto']} {finding['service']} - {finding['version_raw']}"
        blocks.append(f"{header}\n\n{text.strip()}{note_block}")
    return "\n\n".join(blocks)


def generate_recommendations_per_finding(with_evidence, model, url, temperature,
                                           timeout, max_tokens, rag_chunks,
                                           known_cves, known_ports_set, vuln_evidence,
                                           warnings, described_ports=None):
    tiers = {"Immediate": [], "Short-term": [], "Long-term": []}
    for finding in with_evidence:
        facts = build_single_finding_facts(finding)
        context = with_reference_context(facts, rag_chunks)
        prompt = (
            f"{context}\n\n"
            "Write ONE short remediation recommendation (2-3 sentences) for "
            "this finding, based only on the facts given above. Never mention "
            "any other port, service, or CVE ID. Do not name a specific "
            "product/vendor variant unless that exact name is already present "
            "in the version string or CVE description above. Do not include a markdown "
            "heading or priority label - plain prose only, that will be "
            "placed under a priority section by the report template."
        )
        label = f"{finding['port']}/{finding['proto']} {finding['service']}"
        print(f"[*] Generating: Recommendations - {label}...")
        text = _generate_and_check_finding_text(
            prompt, model, url, temperature, timeout, max_tokens,
            known_cves, known_ports_set, vuln_evidence, warnings,
            "Recommendations", label, described_ports,
        )
        cve_ids = ", ".join(c["id"] for c in finding.get("cves", []))
        header = f"**{finding['port']}/{finding['proto']} {finding['service']}" + \
                 (f" ({cve_ids})**" if cve_ids else "**")
        tier = priority_tier(finding_max_cvss(finding))
        tiers[tier].append(f"- {header}: {text.strip()}")

    parts = []
    for tier_name in ("Immediate", "Short-term", "Long-term"):
        if tiers[tier_name]:
            parts.append(f"### {tier_name}\n\n" + "\n".join(tiers[tier_name]))
    return "\n\n".join(parts) if parts else "No findings with CVEs/exploits required remediation in this scan."


SECTION_PROMPTS = {
    "executive_summary": ("Executive Summary", prompt_executive_summary),
    "technical_findings": ("Technical Findings", prompt_technical_findings),
    "recommendations": ("Recommendations", prompt_recommendations),
}


# ----------------------------------------------------------------------------
# Deterministic facts table (never touched by the model)
# ----------------------------------------------------------------------------


def render_facts_table(session):
    lines = ["## Findings Reference Table", "",
             "| Port/Proto | Service | Version | CVEs | Exploits |",
             "|---|---|---|---|---|"]
    for f in session.get("cve_exploit_findings", []):
        cve_str = ", ".join(c["id"] for c in f.get("cves", [])) or "-"
        exp_str = ", ".join(e.get("title", "?") for e in f.get("exploits", [])) or "-"
        lines.append(
            f"| {f['port']}/{f['proto']} | {f['service']} | {f['version_raw']} | "
            f"{cve_str} | {exp_str} |"
        )
    if not session.get("cve_exploit_findings"):
        lines.append("| - | - | - | - | - |")
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# Report assembly
# ----------------------------------------------------------------------------


def generate_report(session, model=DEFAULT_MODEL, url=OLLAMA_DEFAULT_URL,
                     temperature=DEFAULT_TEMPERATURE, sections=None, dry_run=False,
                     use_rag=False, vectorstore_path=DEFAULT_VECTORSTORE_PATH,
                     collection_name=DEFAULT_COLLECTION_NAME,
                     embed_model=DEFAULT_EMBED_MODEL, rag_k=DEFAULT_RAG_K,
                     max_findings=MAX_FACTS_FINDINGS, timeout=300, max_tokens=900):
    sections = sections or SECTION_ORDER
    facts = build_facts_context(session, max_findings=max_findings)
    known_cves = known_cve_ids(session)
    known_ports_set = known_ports(session)
    vuln_evidence = build_vuln_class_evidence(session)
    described_ports = build_described_port_mentions(session)

    # Evidence-only facts: services with zero CVEs/exploits are never shown
    # to the model for narrative sections that walk through findings - this
    # closes off the exact gap where a model, faced with a wall of "CVEs:
    # none found" lines, was filling the perceived gap by inventing plausible
    # -sounding CVE IDs and vulnerability classes instead of just saying so.
    with_evidence, without_evidence = split_findings_by_evidence(session)
    focused_session = dict(session, cve_exploit_findings=with_evidence)
    focused_session.pop("vulnerability_scan", None)  # keep the unattributed CVE
    # count out of technical_findings/recommendations entirely - only the
    # executive summary (full facts) should reference it, and only as a count
    focused_facts = build_facts_context(focused_session, max_findings=max_findings)
    no_evidence_block = render_no_evidence_list(without_evidence)

    rag_chunks = []
    rag_warning = None

    if use_rag:
        try:
            rag_query = build_rag_query(session)
            rag_chunks = retrieve_rag_context(
                rag_query,
                k=rag_k,
                vectorstore_path=vectorstore_path,
                collection_name=collection_name,
                embed_model=embed_model,
                url=url,
            )
            print(f"[*] Retrieved {len(rag_chunks)} RAG context chunk(s).")
        except RuntimeError as e:
            rag_warning = f"RAG context unavailable: {e}"
            eprint(f"[!] {rag_warning}")

    generated = {}
    warnings = [rag_warning] if rag_warning else []

    for key in sections:
        if key not in SECTION_PROMPTS:
            eprint(f"[!] Unknown section '{key}', skipping.")
            continue
        title, prompt_fn = SECTION_PROMPTS[key]

        if dry_run:
            print(f"\n{'=' * 60}\n[DRY RUN] {title}\n{'=' * 60}")
            generated[key] = f"[dry-run - {title} not generated]"
            continue

        # technical_findings and recommendations are generated per-finding
        # (one short focused call per finding, assembled deterministically)
        # rather than one big call - see the module docstring above
        # generate_technical_findings_per_finding for why: a single call
        # asked to cover every finding proved unreliable at 3B scale,
        # including skipping the single highest-severity finding in a real
        # scan. executive_summary stays a single call since it's meant to
        # synthesize an overview, not enumerate every finding individually.
        if key == "technical_findings":
            text = generate_technical_findings_per_finding(
                with_evidence, model, url, temperature, timeout, max_tokens,
                rag_chunks, known_cves, known_ports_set, vuln_evidence, warnings,
                described_ports,
            )
            if no_evidence_block:
                text = text.rstrip() + "\n\n" + no_evidence_block
            generated[key] = text
            continue

        if key == "recommendations":
            text = generate_recommendations_per_finding(
                with_evidence, model, url, temperature, timeout, max_tokens,
                rag_chunks, known_cves, known_ports_set, vuln_evidence, warnings,
                described_ports,
            )
            generated[key] = text
            continue

        # executive_summary: single call using the full facts (with totals)
        user_prompt = prompt_fn(facts, rag_chunks)
        print(f"[*] Generating: {title} (model={model})...")
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ]
        try:
            text = call_ollama(messages, model=model, url=url, temperature=temperature,
                                timeout=timeout, max_tokens=max_tokens)
        except RuntimeError as e:
            eprint(f"[!] {e}")
            text = f"[Generation failed: {e}]"

        text = strip_duplicate_heading(text, title)

        bad_cves = check_grounding(text, known_cves)
        if bad_cves:
            warn = (f"Section '{title}' mentions CVE ID(s) not present in session.json "
                    f"(possible hallucination): {', '.join(bad_cves)}")
            eprint(f"[!] {warn}")
            warnings.append(warn)

        bad_ports = check_port_grounding(text, known_ports_set, described_ports)
        if bad_ports:
            warn = (f"Section '{title}' references port(s) not found anywhere in "
                     f"session.json (likely a fabricated finding): {', '.join(bad_ports)}")
            eprint(f"[!] {warn}")
            warnings.append(warn)

        bad_vuln_classes = check_vuln_class_grounding(text, vuln_evidence)
        if bad_vuln_classes:
            warn = (f"Section '{title}' asserts vulnerability type(s) not supported by "
                     f"any CVE description or exploit title in session.json (possible "
                     f"unsupported claim): {', '.join(bad_vuln_classes)}")
            eprint(f"[!] {warn}")
            warnings.append(warn)

        generated[key] = text

    return generated, warnings, facts


def render_markdown(session, generated, warnings):
    lines = []
    lines.append(f"# Sudarshan Assessment Report")
    lines.append("")
    lines.append(f"**Target:** {session.get('target', 'unknown')}  ")
    lines.append(f"**Engagement:** {session.get('friendly_name', 'unknown')}  ")
    lines.append(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("> Narrative sections in this report were AI-generated with a local "
                  "Ollama model from the structured facts in session.json, optionally "
                  "supported by local vector-store context. The findings table below is "
                  "generated directly from JSON, not by the model, and is the "
                  "authoritative source of truth. Any AI-mentioned CVE not present in "
                  "that table is flagged in the Grounding Check appendix.")
    lines.append("")

    if "executive_summary" in generated:
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(generated["executive_summary"])
        lines.append("")

    lines.append(render_facts_table(session))
    lines.append("")

    if "technical_findings" in generated:
        lines.append("## Technical Findings")
        lines.append("")
        lines.append(generated["technical_findings"])
        lines.append("")

    if "recommendations" in generated:
        lines.append("## Recommendations")
        lines.append("")
        lines.append(generated["recommendations"])
        lines.append("")

    lines.append("## Appendix: Grounding Check")
    lines.append("")
    if warnings:
        lines.append("The following possible issues were detected automatically:")
        lines.append("")
        for w in warnings:
            lines.append(f"- ⚠️ {w}")
    else:
        lines.append("No hallucinated CVE IDs detected - every CVE mentioned in the "
                      "narrative sections above traces back to session.json.")
    lines.append("")

    return "\n".join(lines)


# ----------------------------------------------------------------------------
# Export: Markdown -> DOCX / PDF
# ----------------------------------------------------------------------------
#
# The generated report is always written as Markdown first (source of
# truth). These functions convert that same Markdown into .docx and/or
# .pdf as an additional, optional step - they never re-derive facts, they
# just re-render the same text.
#
#   export_docx() - pure python-docx markdown parser. No external deps
#                    beyond python-docx. Supports #/##/### headers, tables,
#                    bullet/numbered lists, blockquotes, code fences, and
#                    **bold** inline text.
#   export_pdf()  - tries pandoc first (best typographic output, requires
#                    pandoc + a PDF engine such as a LaTeX distribution or
#                    wkhtmltopdf on PATH). If pandoc is missing or the
#                    conversion fails for any reason (e.g. no PDF engine
#                    installed), it falls back to export_pdf_fallback(),
#                    a pure-Python renderer using fpdf2 - plainer looking,
#                    but has no external system dependencies.

TABLE_SEPARATOR_RE = re.compile(r"^\|?[\s:\-|]+\|?$")
BOLD_SPLIT_RE = re.compile(r"(\*\*.+?\*\*)")


def _docx_add_runs(paragraph, text):
    """Add text to a python-docx paragraph, honoring **bold** spans."""
    for part in BOLD_SPLIT_RE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**") and len(part) > 4:
            run = paragraph.add_run(part[2:-2])
            run.bold = True
        else:
            paragraph.add_run(part)


def export_docx(report_md, out_path):
    """Render a Markdown report string to a .docx file at out_path."""
    try:
        import docx
    except ImportError:
        raise RuntimeError(
            "DOCX export needs python-docx. Install with: pip install python-docx"
        )

    document = docx.Document()
    style_names = {s.name for s in document.styles}

    lines = report_md.split("\n")
    i = 0
    in_code_block = False

    while i < len(lines):
        raw_line = lines[i]
        stripped = raw_line.strip()

        # Fenced code blocks (```...```) - render as monospace paragraphs
        if stripped.startswith("```"):
            in_code_block = not in_code_block
            i += 1
            continue

        if in_code_block:
            p = document.add_paragraph(raw_line if raw_line.strip() else " ")
            for run in p.runs:
                run.font.name = "Consolas"
                run.font.size = docx.shared.Pt(9)
            i += 1
            continue

        if not stripped:
            i += 1
            continue

        # Headers
        if stripped.startswith("### "):
            document.add_heading(stripped[4:].strip(), level=3)
            i += 1
            continue
        if stripped.startswith("## "):
            document.add_heading(stripped[3:].strip(), level=2)
            i += 1
            continue
        if stripped.startswith("# "):
            document.add_heading(stripped[2:].strip(), level=1)
            i += 1
            continue

        # Blockquote (used for the intro note + grounding warnings)
        if stripped.startswith(">"):
            p = document.add_paragraph()
            if "Intense Quote" in style_names:
                p.style = "Intense Quote"
            _docx_add_runs(p, stripped.lstrip(">").strip())
            i += 1
            continue

        # Markdown table -> native Word table
        if stripped.startswith("|"):
            table_lines = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                table_lines.append(lines[i].strip())
                i += 1
            rows = [
                [c.strip() for c in tl.strip("|").split("|")]
                for tl in table_lines
                if not TABLE_SEPARATOR_RE.match(tl)
            ]
            if rows:
                n_cols = max(len(r) for r in rows)
                table = document.add_table(rows=0, cols=n_cols)
                if "Light Grid Accent 1" in style_names:
                    table.style = "Light Grid Accent 1"
                for r_idx, row in enumerate(rows):
                    cells = table.add_row().cells
                    for c_idx in range(n_cols):
                        text = row[c_idx] if c_idx < len(row) else ""
                        cells[c_idx].text = text
                        if r_idx == 0:
                            for para in cells[c_idx].paragraphs:
                                for run in para.runs:
                                    run.bold = True
            continue

        # Bullet list
        if stripped.startswith("- ") or stripped.startswith("* "):
            p = document.add_paragraph(style="List Bullet")
            _docx_add_runs(p, stripped[2:].strip())
            i += 1
            continue

        # Numbered list
        if re.match(r"^\d+\.\s", stripped):
            p = document.add_paragraph(style="List Number")
            _docx_add_runs(p, re.sub(r"^\d+\.\s", "", stripped))
            i += 1
            continue

        # Plain paragraph
        p = document.add_paragraph()
        _docx_add_runs(p, stripped)
        i += 1

    document.save(out_path)
    return out_path


def export_pdf_fallback(report_md, out_path):
    """Pure-Python PDF renderer (fpdf2). Plainer than pandoc output but has
    no external system dependencies - used automatically when pandoc isn't
    available or fails (e.g. no LaTeX/wkhtmltopdf engine installed)."""
    try:
        from fpdf import FPDF
    except ImportError:
        raise RuntimeError(
            "PDF export needs either 'pandoc' (+ a PDF engine) on PATH, or "
            "the 'fpdf2' Python package. Install with: pip install fpdf2"
        )

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=11)

    def safe(text):
        # Core PDF fonts only support latin-1 - degrade unicode (emoji,
        # smart quotes, etc.) gracefully instead of crashing the export.
        return text.encode("latin-1", "replace").decode("latin-1")

    def soft_wrap(text, chunk=60):
        # Insert a break opportunity into any unbroken run of 'chunk'+
        # characters (long URLs, hashes, etc.) so fpdf always has
        # somewhere to wrap - prevents "not enough horizontal space"
        # crashes on content we don't fully control (facts pulled from
        # scan output).
        return re.sub(rf"(\S{{{chunk}}})(?=\S)", r"\1 ", text)

    def render_line(cell_call, *cell_args):
        try:
            cell_call(*cell_args)
        except Exception:
            wrapped_args = list(cell_args)
            wrapped_args[-1] = soft_wrap(wrapped_args[-1])
            try:
                cell_call(*wrapped_args)
            except Exception:
                pass  # last resort: skip a single unrenderable line rather than abort the export

    for raw_line in report_md.split("\n"):
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped:
            pdf.ln(4)
            continue

        # Markdown table separator rows (e.g. "|---|---|---|") are a single
        # unbreakable token with no spaces - fpdf can't wrap them and will
        # raise "not enough horizontal space". They add nothing visually
        # in a plain-text PDF anyway, so just skip them.
        if stripped.startswith("|") and TABLE_SEPARATOR_RE.match(stripped):
            continue

        text = safe(re.sub(r"\*\*(.+?)\*\*", r"\1", stripped))

        if stripped.startswith("### "):
            pdf.set_font("Helvetica", "B", 12)
            render_line(pdf.multi_cell, 0, 7, text[4:])
            pdf.set_font("Helvetica", size=11)
        elif stripped.startswith("## "):
            pdf.set_font("Helvetica", "B", 13)
            render_line(pdf.multi_cell, 0, 8, text[3:])
            pdf.set_font("Helvetica", size=11)
        elif stripped.startswith("# "):
            pdf.set_font("Helvetica", "B", 16)
            render_line(pdf.multi_cell, 0, 9, text[2:])
            pdf.set_font("Helvetica", size=11)
        elif stripped.startswith(("- ", "* ")):
            render_line(pdf.multi_cell, 0, 6, f"    - {text.lstrip('-* ').strip()}")
        elif stripped.startswith("|"):
            pdf.set_font("Courier", size=8)
            render_line(pdf.multi_cell, 0, 5, text)
            pdf.set_font("Helvetica", size=11)
        elif stripped.startswith(">"):
            pdf.set_font("Helvetica", "I", 10)
            render_line(pdf.multi_cell, 0, 6, text.lstrip(">").strip())
            pdf.set_font("Helvetica", size=11)
        else:
            render_line(pdf.multi_cell, 0, 6, text)

    pdf.output(out_path)
    return out_path


def export_pdf(report_md, out_path):
    """Convert the Markdown report to PDF. Tries pandoc first, falls back
    to a pure-Python renderer automatically on any failure."""
    if shutil.which("pandoc"):
        tmp_md = out_path + ".tmp.md"
        try:
            with open(tmp_md, "w", encoding="utf-8") as f:
                f.write(report_md)
            result = subprocess.run(
                ["pandoc", tmp_md, "-o", out_path],
                capture_output=True, text=True, timeout=120,
            )
            if result.returncode == 0 and os.path.isfile(out_path):
                return out_path
            eprint(f"[!] pandoc PDF conversion failed, falling back to built-in "
                   f"renderer: {result.stderr.strip()[:300]}")
        except Exception as e:
            eprint(f"[!] pandoc PDF conversion error, falling back to built-in "
                   f"renderer: {e}")
        finally:
            if os.path.isfile(tmp_md):
                os.remove(tmp_md)

    return export_pdf_fallback(report_md, out_path)


def export_report(report_md, out_dir, base_name="report", formats=None):
    """Export an already-rendered Markdown report string to additional
    formats. formats: iterable of 'docx' / 'pdf'. Returns a dict keyed by
    format with {"ok": bool, "path"|"error": ...} - never raises, so a
    failed docx export (e.g. missing dependency) doesn't block a
    subsequent pdf export or the caller's flow."""
    formats = formats or []
    os.makedirs(out_dir, exist_ok=True)
    results = {}
    for fmt in formats:
        fmt = fmt.lower().strip()
        if fmt not in ("docx", "pdf"):
            results[fmt] = {"ok": False, "error": f"Unsupported export format: {fmt}"}
            continue
        target_path = os.path.join(out_dir, f"{base_name}.{fmt}")
        try:
            if fmt == "docx":
                export_docx(report_md, target_path)
            else:
                export_pdf(report_md, target_path)
            results[fmt] = {"ok": True, "path": target_path}
        except RuntimeError as e:
            results[fmt] = {"ok": False, "error": str(e)}
    return results


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------


def build_arg_parser():
    p = argparse.ArgumentParser(
        description="Sudarshan Phase 3: generate report narrative from session.json via Ollama.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--session", required=False, help="Path to session.json (from session_builder.py)")
    p.add_argument("--out", default=None, help="Output markdown path (default: <session dir>/report.md)")
    p.add_argument("--model", default=DEFAULT_MODEL, help=f"Ollama model name (default: {DEFAULT_MODEL})")
    p.add_argument("--ollama-url", default=OLLAMA_DEFAULT_URL, help=f"Ollama server URL (default: {OLLAMA_DEFAULT_URL})")
    p.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    p.add_argument("--timeout", type=int, default=300,
                    help="Ollama request timeout in seconds per section (default: 300). "
                         "Raise this on slow/CPU-only/low-RAM machines.")
    p.add_argument("--max-tokens", type=int, default=900,
                    help="Max tokens the model may generate per section (default: 900). "
                         "Lower = faster + less room to ramble/fabricate; raise if "
                         "sections are getting cut off mid-sentence.")
    p.add_argument("--max-findings", type=int, default=MAX_FACTS_FINDINGS,
                    help="Cap on service findings included in the prompt context")
    p.add_argument("--sections", default=",".join(SECTION_ORDER),
                    help=f"Comma-separated sections to generate (default: all - {','.join(SECTION_ORDER)})")
    p.add_argument("--dry-run", action="store_true",
                    help="Print prompts without calling Ollama (prompt-engineering mode)")
    p.add_argument("--rag", action="store_true",
                    help="Retrieve supporting context from the local ChromaDB vector store")
    p.add_argument("--vectorstore", default=DEFAULT_VECTORSTORE_PATH,
                    help=f"ChromaDB path for RAG context (default: {DEFAULT_VECTORSTORE_PATH})")
    p.add_argument("--collection", default=DEFAULT_COLLECTION_NAME,
                    help=f"ChromaDB collection name (default: {DEFAULT_COLLECTION_NAME})")
    p.add_argument("--embed-model", default=DEFAULT_EMBED_MODEL,
                    help=f"Ollama embedding model for RAG (default: {DEFAULT_EMBED_MODEL})")
    p.add_argument("--rag-k", type=int, default=DEFAULT_RAG_K,
                    help=f"Number of RAG context chunks to retrieve (default: {DEFAULT_RAG_K})")
    p.add_argument("--seed-rag", action="store_true",
                    help="Seed the vector store with starter context, then exit")
    p.add_argument("--ingest-context", action="append", default=[],
                    help="Add a text/markdown/json/pdf/docx file to the RAG vector store")
    p.add_argument("--source-label", default=None,
                    help="Optional source label to store with ingested context")
    p.add_argument("--chunk-chars", type=int, default=1800,
                    help="Approximate max characters per ingested context chunk")
    p.add_argument("--chunk-overlap", type=int, default=250,
                    help="Character overlap between ingested context chunks")
    p.add_argument("--export", default=None,
                    help="Additional export format(s) beyond Markdown: 'docx', "
                         "'pdf', a comma-separated combo (e.g. 'docx,pdf'), or "
                         "'both'/'all' for both. Markdown is always written.")
    return p


def main():
    args = build_arg_parser().parse_args()

    global MAX_FACTS_FINDINGS
    sections = [s.strip() for s in args.sections.split(",") if s.strip()]

    if args.seed_rag:
        try:
            added = seed_example_context(
                vectorstore_path=args.vectorstore,
                collection_name=args.collection,
                embed_model=args.embed_model,
                url=args.ollama_url,
            )
        except RuntimeError as e:
            eprint(f"[!] Could not seed RAG context: {e}")
            sys.exit(1)
        print(f"[+] Seeded {added} starter context chunk(s) into {args.vectorstore}")
        return

    if args.ingest_context:
        total = 0
        for path in args.ingest_context:
            try:
                result = ingest_context_file(
                    path,
                    source_label=args.source_label,
                    vectorstore_path=args.vectorstore,
                    collection_name=args.collection,
                    embed_model=args.embed_model,
                    url=args.ollama_url,
                    max_chars=args.chunk_chars,
                    overlap_chars=args.chunk_overlap,
                )
            except (RuntimeError, FileNotFoundError) as e:
                eprint(f"[!] Could not ingest {path}: {e}")
                sys.exit(1)
            total += result["chunks"]
            print(f"[+] Ingested {result['chunks']} chunk(s) from {result['path']}")
        print(f"[+] Total context chunks added: {total}")
        return

    if not args.session:
        eprint("[!] --session is required unless you are using --seed-rag or --ingest-context")
        sys.exit(1)

    if not os.path.isfile(args.session):
        eprint(f"[!] Session file not found: {args.session}")
        sys.exit(1)

    with open(args.session) as f:
        session = json.load(f)

    if not args.dry_run:
        models = list_ollama_models(args.ollama_url)
        if models is not None and args.model not in models and not any(
            m.startswith(args.model + ":") for m in models
        ):
            eprint(f"[!] Model '{args.model}' not found on {args.ollama_url}. "
                   f"Installed models: {models or '(none, or Ollama unreachable)'}")
            eprint(f"[!] Pull it with: ollama pull {args.model}")
            sys.exit(1)

    generated, warnings, facts = generate_report(
        session,
        model=args.model,
        url=args.ollama_url,
        temperature=args.temperature,
        sections=sections,
        dry_run=args.dry_run,
        use_rag=args.rag,
        vectorstore_path=args.vectorstore,
        collection_name=args.collection,
        embed_model=args.embed_model,
        rag_k=args.rag_k,
        max_findings=args.max_findings,
        timeout=args.timeout,
        max_tokens=args.max_tokens,
    )

    if args.dry_run:
        print(f"\n{'=' * 60}\n[DRY RUN] Facts context used for every prompt above\n{'=' * 60}")
        print(facts)
        return

    report_md = render_markdown(session, generated, warnings)
    out_path = args.out or os.path.join(os.path.dirname(os.path.abspath(args.session)), "report.md")
    with open(out_path, "w") as f:
        f.write(report_md)
    print(f"\n[+] Report saved to {out_path}")
    if warnings:
        print(f"[!] {len(warnings)} grounding warning(s) - see Appendix in the report.")

    if args.export:
        fmt_arg = args.export.lower().strip()
        formats = ["docx", "pdf"] if fmt_arg in ("both", "all") else [
            f.strip() for f in fmt_arg.split(",") if f.strip()
        ]
        out_dir = os.path.dirname(os.path.abspath(out_path))
        base_name = os.path.splitext(os.path.basename(out_path))[0]
        export_results = export_report(report_md, out_dir, base_name=base_name, formats=formats)
        for fmt, res in export_results.items():
            if res["ok"]:
                print(f"[+] {fmt.upper()} report saved to {res['path']}")
            else:
                eprint(f"[!] {fmt.upper()} export failed: {res['error']}")


if __name__ == "__main__":
    main()

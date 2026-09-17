"""
Shared configuration for Wired v1.0 (sudarshan.py, cve_lookup.py, report_generator.py).

IMPORTANT: Never hardcode API keys or secrets in this file. It's committed to
GitHub. Secrets belong in a local, git-ignored .env file (see .env.example)
or exported directly in your shell profile - both are read automatically
via environment variables, never edited here.
"""

import os

# ----------------------------------------------------------------------------
# Ollama / model settings
# ----------------------------------------------------------------------------
OLLAMA_DEFAULT_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")

# Switched to 7B for the OCI deployment (2 OCPU / 12GB Ampere A1 - Always
# Free tier as of the June 2026 policy change) - comfortably fits in RAM.
# If generation feels slow on 2 vCPUs, drop to "qwen2.5:3b-instruct" here;
# no other code changes needed, it's a pure config swap.
REPORT_MODEL = "qwen2.5:7b-instruct"
EMBED_MODEL = "nomic-embed-text"

# ----------------------------------------------------------------------------
# RAG / vector store
# ----------------------------------------------------------------------------
VECTORSTORE_DIR = "vectorstore"
VECTORSTORE_COLLECTION = "context_library"

# ----------------------------------------------------------------------------
# NVD API
# ----------------------------------------------------------------------------
# Read from environment only - see .env.example. Without a key: 5 req/30s.
# With a key: 50 req/30s. cve_lookup.py and sudarshan.py already read this same
# variable directly via os.environ.get("NVD_API_KEY"); it's re-exposed here
# too so any module that imports sudarshan_config can use it consistently.
NVD_API_KEY = os.environ.get("0312c151-8663-4808-8928-5195a0884138")

# ----------------------------------------------------------------------------
# Output Management
# ----------------------------------------------------------------------------
# All session logs, markdown reports, and PDFs will be saved here.
OUTPUT_DIR = "/mnt/e/Sudarshan-AI/Test Reports"

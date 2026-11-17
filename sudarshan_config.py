"""
Shared configuration for Sudarshan (sudarshan.py, cve_lookup.py,
report_generator.py, session_builder.py).

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

# setup.sh picks a model that fits this machine's RAM/CPU/GPU and writes it to
# .env as SUDARSHAN_MODEL. You can override it any time by editing .env (or
# exporting SUDARSHAN_MODEL), e.g. SUDARSHAN_MODEL=qwen2.5:3b-instruct.
# The fallback below is only used when nothing has been configured.
DEFAULT_REPORT_MODEL = "qwen2.5:7b-instruct"
REPORT_MODEL = os.environ.get("SUDARSHAN_MODEL", "").strip() or DEFAULT_REPORT_MODEL
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
# With a key: 50 req/30s. cve_lookup.py and sudarshan.py read this same
# variable directly via os.environ.get("NVD_API_KEY"); it's re-exposed here
# too so any module that imports sudarshan_config can use it consistently.
NVD_API_KEY = os.environ.get("NVD_API_KEY")

# Sudarshan

**A local-first, AI-assisted penetration-test report pipeline.** Scan a lab target, look up real CVEs and public exploits, and generate a grounded Markdown / Word / PDF report with a local LLM - everything runs on your own machine.

```
recon scans -> CVE + exploit lookup -> session.json -> local LLM (Ollama) -> grounded report
```

Its core design rule is **hallucination resistance**: every claim in the AI-written report must trace back to real scan data or be flagged. The pipeline checks generated text for invented CVE IDs, invented ports, vulnerability classes that nothing in the data supports, and text that drifted into the wrong script, and it adds a grounding-check appendix to the report.

> **Authorized use only.** Sudarshan runs real scanners (nmap, gobuster, ffuf, naabu, subfinder, httpx, searchsploit). Only scan systems you own or have explicit written permission to test. You are responsible for how you use it.

## Requirements

- **Linux** with `apt` (Debian, Ubuntu, Kali). Sudarshan is Linux-only - it uses a real pty, nmap and other Linux tools.
- ~10 GB free disk (models and tools), more with PDF support (LaTeX).
- 8 GB RAM minimum recommended; a GPU (NVIDIA, 6 GB+ VRAM) makes AI reports much faster.
- `sudo` access for `setup.sh` (installs system packages).

## Quick start

```bash
git clone https://github.com/srirampb22/Sudarshan sudarshan
cd sudarshan
bash setup.sh        # one time: tools, Ollama, a model that fits your machine, Python env
bash run.sh          # starts the web UI and opens your browser
```

`setup.sh` is safe to re-run. Useful flags: `--no-pdf` (skip pandoc/LaTeX, saves ~500 MB), `--model NAME` (choose the Ollama model yourself).

`run.sh` serves the UI on `http://127.0.0.1:8000` and prints a one-time link like `http://127.0.0.1:8000/?token=...`. Open that link (it opens automatically when you have a desktop). Flags: `--no-browser`, `--port N`.

## Using it

Inside the web terminal you get Sudarshan's numbered menu: host discovery, port/service scans, web directory enumeration, subdomain and HTTP probing, vulnerability scripts, CVE/exploit lookup, and option **[12] Generate AI Report**, which builds `session.json` (if needed) and writes the report, optionally exporting Word and PDF. The Dashboard lists your targets, running sessions, and lets you download or delete results. Results live in `./sudarshan-results/<target>/`.

You can also run the stages directly from the project folder (with `source venv/bin/activate`):

```bash
python3 sudarshan.py                                  # interactive menu in your terminal
python3 report_generator.py --session path/to/session.json --rag
```

### Choosing the AI model

`setup.sh` picks a Qwen2.5-Instruct model from your RAM/GPU and stores it as `SUDARSHAN_MODEL` in `.env`:

| Your machine | Model |
|---|---|
| GPU with 6 GB+ VRAM, or 10 GB+ RAM | `qwen2.5:7b-instruct` |
| 6-10 GB RAM | `qwen2.5:3b-instruct` |
| 3.5-6 GB RAM | `qwen2.5:1.5b-instruct` |
| less | `qwen2.5:0.5b-instruct` (quality will be poor) |

Edit `SUDARSHAN_MODEL` in `.env` any time (then `ollama pull <model>`). Smaller models are faster but write less detailed reports; the grounding checks still apply.

### Optional: RAG context

Reports can be enriched with background from pentest-report PDFs/notes you provide. Only a tiny starter seed ships with the repo; build your own store from material you have the right to use:

```bash
python3 report_generator.py --seed-rag                       # starter seed
python3 report_generator.py --ingest-context /path/to/file   # .txt .md .json .pdf .docx
```

## Safety model

**Targets.** Scanning is default-deny. Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) are allowed. Loopback, link-local and cloud-metadata addresses are always blocked. Anything else needs to be listed in `SUDARSHAN_ALLOWED_TARGETS` (IPs, CIDRs or domains) in `.env`; blocks can be added with `SUDARSHAN_DENIED_TARGETS`. Hostnames are resolved and *every* address must pass. Targets with shell metacharacters are rejected. Every attempt (allowed or rejected) is appended to a local audit log (`~/sudarshan-audit.log`) - your own record, never transmitted.

**Web UI.** There are no accounts. The server listens on `127.0.0.1` only, and every route - including the terminal WebSocket, which runs a real shell - requires a random token generated fresh each time you run `run.sh`, plus a same-origin check. This stops other web pages open in your browser from reaching the terminal. The token lives in the URL printed at start-up; don't share it. Stop the server with Ctrl+C.

## Privacy

- Target IPs, scan output and reports never leave your machine. The AI runs locally through Ollama.
- CVE lookups send **service/version strings** (for example `vsftpd 2.3.4`) to the public NVD API, never the target address. An optional free `NVD_API_KEY` raises the rate limit.
- Setup downloads packages, Ollama, models, searchsploit and ProjectDiscovery tool releases from their official sources.

## Configuration

All settings are environment variables, normally kept in `.env` (see `.env.example`): `NVD_API_KEY`, `SUDARSHAN_MODEL`, `SUDARSHAN_ALLOWED_TARGETS`, `SUDARSHAN_DENIED_TARGETS`, `SUDARSHAN_RESULTS_DIR`, `SUDARSHAN_AUDIT_LOG_FILE`, `SUDARSHAN_PORT`, `OLLAMA_URL`. `.env` is git-ignored; never commit it.

## Development

```bash
pip install -r requirements-dev.txt
python3 -m pytest                    # grounding, grouping, allowlist, parsing, web guard, shell scripts
bash check_secrets_hygiene.sh        # run before every push
```

Layout: `sudarshan.py` (menu and scanning), `cve_lookup.py` (NVD + searchsploit), `session_builder.py` (scan output to `session.json`), `report_generator.py` (grounded report generation and export), `sudarshan_config.py`, `pick_model.py`, `web_terminal/` (FastAPI web UI), `tests/`.

## Known limitations

- Linux only; `setup.sh` supports apt-based distributions.
- Reports depend on the local model: small models write shorter, less polished text. Always review a report before sharing it.
- The grounding checks catch invented CVEs, ports and vulnerability classes, not every possible factual or wording error.
- DNS can change between the target check and the scan.
- Without LaTeX/pandoc, PDF export falls back to a plainer built-in renderer.
- CVE matching is keyword-based on service banners, so it can miss findings or include loose matches.

## License

MIT - see [LICENSE](LICENSE).

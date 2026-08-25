# Sudarshan

Local, offline-first AI pentest report pipeline. Scan → CVE/exploit lookup → grounded AI narrative → Markdown/Word/PDF report.

No cloud AI, no data leaves your machine except NVD/ExploitDB lookups.

```
Recon scan → session.json → Ollama + local RAG → grounded report
```

## Requirements

- Linux (Ubuntu/Kali) with `nmap`, `gobuster`, `searchsploit`
- Python 3.10+
- [Ollama](https://ollama.com)
- Free [NVD API key](https://nvd.nist.gov/developers/request-an-api-key) (optional but recommended)

## Setup

```bash
git clone <this-repo>
cd sudarshan
cp .env.example .env && nano .env   # add your NVD_API_KEY
chmod +x setup.sh
./setup.sh
```

Windows/local dev: run `setup.bat` instead (full exploit lookup requires WSL2).

## Usage

```bash
source .env
source venv/bin/activate
python3 sudarshan.py
```

Menu-driven. Typical flow: `[2]` Host Discovery → `[3]` Port Scanning → `[11]` Build Structured Findings → `[12]` Generate AI Report.

Results saved under `~/sudarshan-results/<target>/`.

## Grounding

Every AI-generated finding traces back to real scan data — CVE IDs, ports, and vulnerability classes are cross-checked against `session.json` before the report is finalized. Anything unverifiable is flagged in the report's Appendix, not silently included.

## Authorized use only

Only run against systems you own or have explicit written authorization to test.

## License

MIT (or your choice — update before publishing)

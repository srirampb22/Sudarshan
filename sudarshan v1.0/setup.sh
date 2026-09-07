#!/usr/bin/env bash
# Sudarshan - setup script for Ubuntu (tested target: OCI Ampere A1, ARM64)
set -e

echo "============================================"
echo "  Sudarshan - Setup"
echo "============================================"
echo

echo "[1/7] Installing system packages..."
sudo apt update
sudo apt install -y python3 python3-venv python3-pip nmap gobuster git curl jq

echo "[2/7] Checking Ollama..."
if ! command -v ollama &> /dev/null; then
    curl -fsSL https://ollama.com/install.sh | sh
else
    echo "Ollama already installed. Skipping."
fi

if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama service..."
    nohup ollama serve > /tmp/ollama.log 2>&1 &
    disown
    sleep 3
fi

echo "Waiting for Ollama to respond..."
for i in {1..10}; do
    if curl -s http://localhost:11434/api/tags > /dev/null; then
        echo "Ollama is up."
        break
    fi
    sleep 2
done

echo "[3/7] Pulling models (qwen2.5:7b-instruct, ~5GB - this takes a while)..."
ollama pull qwen2.5:7b-instruct
ollama pull nomic-embed-text

echo "[4/7] Setting up searchsploit..."
if ! command -v searchsploit &> /dev/null; then
    sudo git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
    sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
    echo "searchsploit installed. Updating database (first run can take a few minutes)..."
    searchsploit -u
else
    echo "searchsploit already installed. Skipping."
fi

echo "Verifying searchsploit flag compatibility..."
if searchsploit -j --disable-colour "test" > /dev/null 2>&1; then
    echo "  OK - '-j --disable-colour' supported."
else
    echo "  [!] WARNING: '-j --disable-colour' failed. Check 'searchsploit --help' and"
    echo "      update the flags in cve_lookup.py's query_searchsploit() if needed."
fi

echo "[5/7] Setting up Python environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate

echo "Installing Python dependencies..."
pip install --quiet --upgrade pip
pip install --quiet -r requirements.txt

echo "[6/7] Checking for .env (NVD_API_KEY)..."
if [ ! -f ".env" ]; then
    echo "  [!] No .env found. Copy .env.example to .env and add your NVD API key:"
    echo "      cp .env.example .env  &&  nano .env"
    echo "  Without it, NVD lookups still work but are rate-limited to 5 req/30s."
else
    echo "  .env found."
fi

echo "[7/7] Seeding RAG vector store..."
[ -f ".env" ] && source .env
python3 report_generator.py --seed-rag || echo "  [!] RAG seed skipped/failed - check chromadb install."

echo
echo "============================================"
echo "  Setup complete."
echo "============================================"
echo
echo "Next steps:"
echo "  1. cp .env.example .env && nano .env   (add NVD_API_KEY, if not done already)"
echo "  2. source .env"
echo "  3. source venv/bin/activate"
echo "  4. python3 sudarshan.py"

#!/usr/bin/env bash
# ==============================================================================
# Trithemius — Automated Setup for macOS & Linux
# ==============================================================================

set -e

# Terminal colors
BOLD='\033[1m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "\n${BOLD}${CYAN}======================================================================${NC}"
echo -e "${BOLD}${CYAN}          TRITHEMIUS — Automated Setup for macOS & Linux            ${NC}"
echo -e "${BOLD}${CYAN}======================================================================${NC}\n"

# 1. Detect suitable Python interpreter (must be >= 3.10 and < 3.14 for AI/CrewAI libraries)
echo -e "${CYAN}[1/5] Checking Python installation...${NC}"

find_python() {
    for candidate in python3.11 python3.12 python3.13 python3.10 /opt/homebrew/bin/python3.11 /opt/homebrew/bin/python3.12 /usr/local/bin/python3.11 python3 /opt/homebrew/bin/python3; do
        if command -v "$candidate" >/dev/null 2>&1; then
            PY_VER=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
            PY_MAJOR=$("$candidate" -c "import sys; print(sys.version_info.major)" 2>/dev/null || echo "0")
            PY_MINOR=$("$candidate" -c "import sys; print(sys.version_info.minor)" 2>/dev/null || echo "0")

            # Check supported range: 3.10 to 3.13
            if [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -ge 10 ] && [ "$PY_MINOR" -le 13 ]; then
                echo "$candidate"
                return 0
            fi
        fi
    done
    return 1
}

PYTHON_BIN=$(find_python || true)

# If no compatible Python (3.10 - 3.13) found:
if [ -z "$PYTHON_BIN" ]; then
    echo -e "  ${YELLOW}! Warning: Current system Python is either < 3.10 or >= 3.14.${NC}"
    echo -e "    Modern AI/LLM packages (CrewAI, Pydantic, ONNX) require ${BOLD}Python 3.10 - 3.13${NC}."

    # If Homebrew is installed, offer automatic installation of python@3.11
    if command -v brew >/dev/null 2>&1; then
        echo -e "\n  ${CYAN}Automating fix via Homebrew: installing python@3.11...${NC}"
        brew install python@3.11 || true
        PYTHON_BIN=$(find_python || true)
    fi
fi

if [ -z "$PYTHON_BIN" ]; then
    echo -e "\n  ${RED}✗ Could not find a compatible Python (3.10, 3.11, 3.12, or 3.13).${NC}"
    echo -e "    Please run in your terminal: ${BOLD}brew install python@3.11${NC}"
    echo -e "    Then re-run: ${BOLD}./install.sh${NC}\n"
    exit 1
fi

PY_VER=$("$PYTHON_BIN" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "  ${GREEN}✓ Using compatible Python: $PYTHON_BIN (v$PY_VER)${NC}"

# 2. Check Ollama installation
echo -e "\n${CYAN}[2/5] Checking Ollama...${NC}"
if command -v ollama >/dev/null 2>&1; then
    OLLAMA_VER=$(ollama --version 2>&1 || echo "installed")
    echo -e "  ${GREEN}✓ Ollama detected ($OLLAMA_VER)${NC}"
else
    echo -e "  ${YELLOW}! Ollama is not installed or not in PATH.${NC}"
    echo -e "    Please install Ollama from: ${BOLD}https://ollama.com/download${NC}"
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo -e "    (Or install via Homebrew: ${BOLD}brew install ollama${NC})"
    fi
    echo -e "    Continuing setup (you can install Ollama later)..."
fi

# 3. Setup Virtual Environment
echo -e "\n${CYAN}[3/5] Setting up Python virtual environment (venv)...${NC}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

# If venv exists with different/incompatible python, recreate it
if [ -d "$VENV_DIR" ]; then
    CURRENT_VENV_PY=$("$VENV_DIR/bin/python" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
    if [ "$CURRENT_VENV_PY" != "$PY_VER" ]; then
        echo -e "  Rebuilding venv to match compatible Python $PY_VER (previous was $CURRENT_VENV_PY)..."
        rm -rf "$VENV_DIR"
    fi
fi

if [ ! -d "$VENV_DIR" ]; then
    echo -e "  Creating virtual environment with $PYTHON_BIN..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    echo -e "  ${GREEN}✓ Virtual environment created.${NC}"
else
    echo -e "  ${GREEN}✓ Existing compatible virtual environment found.${NC}"
fi

# Activate venv
source "$VENV_DIR/bin/activate"

# 4. Install Python dependencies
echo -e "\n${CYAN}[4/5] Installing Python dependencies...${NC}"
pip install --upgrade pip --quiet

# Install core dependencies first
echo -e "  Installing core dependencies (ChromaDB, Ollama, Requests, BeautifulSoup4)..."
pip install chromadb>=0.4.0 ollama>=0.3.0 requests>=2.28.0 beautifulsoup4>=4.12.0

# Install CrewAI agents (handles optional failure gracefully if user overrides python)
echo -e "  Installing multi-agent dependencies (CrewAI)..."
if pip install crewai>=0.80.0 crewai-tools>=0.14.0; then
    echo -e "  ${GREEN}✓ CrewAI multi-agent dependencies installed.${NC}"
else
    echo -e "  ${YELLOW}! CrewAI could not be installed on this specific Python build.${NC}"
    echo -e "    (Note: RAG Assistant, Workstation GUI, Gematria & Walsingham scraper will still run perfectly!)${NC}"
fi

echo -e "  ${GREEN}✓ Dependencies check completed.${NC}"

# 5. Check Ollama models or Cloud Provider Options
echo -e "\n${CYAN}[5/5] Checking Model Inference & Cloud Options...${NC}"

# Check for configured cloud API keys
CLOUD_KEY_FOUND=""
for k in GROQ_API_KEY OPENAI_API_KEY GEMINI_API_KEY ANTHROPIC_API_KEY OPENROUTER_API_KEY; do
    if [ -n "${!k}" ]; then
        CLOUD_KEY_FOUND="$k"
        break
    fi
done

if [ -n "$CLOUD_KEY_FOUND" ]; then
    echo -e "  ${GREEN}✓ Cloud API key detected ($CLOUD_KEY_FOUND).${NC}"
    echo -e "    Skipping local model download (~4.5 GB saved). RAG will stream from cloud provider with 0 VRAM."
elif [[ "$*" == *"--no-pull"* ]] || [[ "$*" == *"--cloud"* ]]; then
    echo -e "  ${GREEN}✓ Cloud / no-pull mode specified. Skipping local model download.${NC}"
elif [ -n "$OLLAMA_HOST" ] && [[ "$OLLAMA_HOST" != *"localhost"* ]] && [[ "$OLLAMA_HOST" != *"127.0.0.1"* ]]; then
    echo -e "  ${GREEN}✓ Remote Ollama host configured ($OLLAMA_HOST). Streaming will occur from remote cloud.${NC}"
elif command -v ollama >/dev/null 2>&1; then
    if curl -s http://localhost:11434/api/tags >/dev/null 2>&1; then
        echo -e "  ${GREEN}✓ Ollama service is active.${NC}"
        echo -e "  Pulling required embeddings model: nomic-embed-text..."
        ollama pull nomic-embed-text || true
        echo -e "  Pulling default LLM: SparkLLM/Spark-X2.5-4B..."
        ollama pull SparkLLM/Spark-X2.5-4B || true
    else
        echo -e "  ${YELLOW}! Local Ollama daemon is not running currently.${NC}"
        echo -e "    Options to run models:"
        echo -e "      1. Local: Start Ollama (${BOLD}ollama serve &${NC}) and pull SparkLLM/Spark-X2.5-4B."
        echo -e "      2. Cloud API (0 VRAM): Pass ${BOLD}--provider groq --api-key <key>${NC} (or openai/gemini/claude)."
        echo -e "      3. Remote Ollama: Set ${BOLD}OLLAMA_HOST=http://remote-server:11434${NC}."
    fi
else
    echo -e "  ${YELLOW}! Local Ollama is not installed.${NC}"
    echo -e "    You can run Trithemius with 0 VRAM using personal API keys (Groq, Gemini, OpenAI, Claude)!"
fi

echo -e "\n${BOLD}${GREEN}======================================================================${NC}"
echo -e "${BOLD}${GREEN}                   SETUP COMPLETED SUCCESSFULLY!                      ${NC}"
echo -e "${BOLD}${GREEN}======================================================================${NC}"
echo -e "\nTo start the Trithemius Terminal Workstation, run:"
echo -e "  ${BOLD}${CYAN}./start.sh${NC}   (or: ${CYAN}python3 trithemius.py${NC})\n"
echo -e "To run with a personal Cloud API key (0 VRAM, 0 model download):"
echo -e "  ${BOLD}${CYAN}python3 trithemius.py --provider groq --api-key <YOUR_KEY>${NC}"
echo -e "  (Or configure inside the app: ${BOLD}/key groq <YOUR_KEY>${NC})\n"
echo -e "To stream models from a remote / cloud Ollama server:"
echo -e "  ${BOLD}${CYAN}python3 trithemius.py --ollama-host http://my-remote-server:11434${NC}\n"
echo -e "To run on low-spec hardware (reduced memory & context window):"
echo -e "  ${BOLD}${CYAN}./start.sh --low-spec${NC}\n"

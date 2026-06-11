#!/bin/bash

# ==========================================
# FixGuard - Arsenal de Ataque Total (macOS)
# ==========================================

echo "🚀 Iniciando instalación del Arsenal FixGuard..."
echo "Este script requiere Homebrew y Go instalados."

# 1. Asegurarnos de que Go y Nmap están instalados via Homebrew
echo "📦 Instalando dependencias base (Nmap, Go)..."
brew install nmap go

# Nota: WPScan se ha retirado de brew, lo usaremos a través de Docker en el orquestador o vía gem si tienes Ruby.

# 2. Configurar el GOPATH para que los binarios funcionen desde cualquier lado
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
echo 'export GOPATH=$HOME/go' >> ~/.zshrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.zshrc

# 3. Descubrimiento Profundo de Endpoints
echo "🕷️ Instalando Katana (ProjectDiscovery Crawler)..."
go install github.com/projectdiscovery/katana/cmd/katana@latest

echo "🕰️ Instalando Waybackurls (AlienVault/Wayback Machine Scraper)..."
go install github.com/tomnomnom/waybackurls@latest

# 4. Reconocimiento de Subdominios
echo "🌍 Instalando Subfinder (Subdomain Enumerator)..."
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 5. XSStrike (XSS Automático)
echo "⚡ Instalando XSStrike..."
mkdir -p tools
cd tools
if [ ! -d "XSStrike" ]; then
    git clone https://github.com/s0md3v/XSStrike.git
    cd XSStrike
    pip3 install -r requirements.txt --break-system-packages 2>/dev/null || pip3 install -r requirements.txt
    cd ..
else
    echo "XSStrike ya está instalado."
fi
cd ..

echo "✅ ¡Arsenal Militar Instalado con Éxito!"
echo "Reinicia tu terminal o corre 'source ~/.zshrc' para que los comandos de Go funcionen globalmente."

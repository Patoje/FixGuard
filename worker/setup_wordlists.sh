#!/bin/bash

# Directorio base
BASE_DIR="$(dirname "$0")/wordlists"
mkdir -p "$BASE_DIR"

# Subdirectorios
mkdir -p "$BASE_DIR/core"
mkdir -p "$BASE_DIR/modern"
mkdir -p "$BASE_DIR/legacy"
mkdir -p "$BASE_DIR/cms"
mkdir -p "$BASE_DIR/payloads"

echo "[FixGuard Wordlists] Actualizando diccionarios de inteligencia..."

# Función helper para descargar
download() {
    local url=$1
    local output=$2
    # Solo descargar si no existe o si queremos forzar actualización. Usamos curl con -s (silencioso)
    curl -s -L "$url" -o "$output"
}

# --- CORE (Todos los stacks) ---
echo "Descargando Core..."
# SecLists raft-small-directories
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-small-directories.txt" "$BASE_DIR/core/raft-small-directories.txt"
# SecLists common api
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt" "$BASE_DIR/core/api-endpoints.txt"
# SecLists common.txt
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" "$BASE_DIR/core/common.txt"
# Trickest Directories
download "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/directories.txt" "$BASE_DIR/core/trickest-directories.txt"

# --- MODERN (APIs, Next, Express, etc.) ---
echo "Descargando Modern/API..."
# GraphQL
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/graphql.txt" "$BASE_DIR/modern/graphql.txt"
# Swagger
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/swagger.txt" "$BASE_DIR/modern/swagger.txt"
# Assetnote API endpoints (ejemplo acortado o usamos seclists)
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints-and-metrics.txt" "$BASE_DIR/modern/api-metrics.txt"
# Assetnote httparchive APIs
download "https://wordlists-cdn.assetnote.io/data/automated/httparchive_apiroutes_2024_05_28.txt" "$BASE_DIR/modern/assetnote-httparchive.txt"
# Trickest APIs
download "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/api.txt" "$BASE_DIR/modern/trickest-api.txt"

# --- LEGACY (PHP, Apache, ASP) ---
echo "Descargando Legacy..."
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/PHP.txt" "$BASE_DIR/legacy/PHP.txt"
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/cgis.txt" "$BASE_DIR/legacy/cgis.txt"
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/IIS.txt" "$BASE_DIR/legacy/IIS.txt"
# FuzzDB CGI
download "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/discovery/predictable-filepaths/filename-dirname-bruteforce/cgi-bin.txt" "$BASE_DIR/legacy/fuzzdb-cgi-bin.txt"

# --- CMS (WordPress, Moodle) ---
echo "Descargando CMS..."
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-plugins.fuzz.txt" "$BASE_DIR/cms/wp-plugins.txt"
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/wp-themes.fuzz.txt" "$BASE_DIR/cms/wp-themes.txt"
# Trickest Wordpress
download "https://raw.githubusercontent.com/trickest/wordlists/main/inventory/wordpress.txt" "$BASE_DIR/cms/trickest-wordpress.txt"

# --- PAYLOADS ---
echo "Descargando Payloads..."
# LFI Jhaddix
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/LFI/LFI-Jhaddix.txt" "$BASE_DIR/payloads/LFI-Jhaddix.txt"
# JWT Weak Secrets
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/jwt.secrets.list" "$BASE_DIR/payloads/jwt.secrets.list"
# SQLi
download "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Fuzzing/SQLi/Generic-SQLi.txt" "$BASE_DIR/payloads/Generic-SQLi.txt"
# PATT XSS
download "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/XSS%20Injection/Intruder/xss-payload-list.txt" "$BASE_DIR/payloads/patt-xss.txt"
# PATT SQLi
download "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/SQL%20Injection/Intruder/sqli-auth-bypass.txt" "$BASE_DIR/payloads/patt-sqli-bypass.txt"
# FuzzDB SQLi
download "https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/attack/sql-injection/detect/xplatform.txt" "$BASE_DIR/payloads/fuzzdb-sqli.txt"

echo "[FixGuard Wordlists] ¡Actualización completa!"

#!/bin/bash

# start.sh - FixGuard Mac/Linux Startup Script

echo "=========================================="
echo "    FixGuard Personal Arsenal Edition     "
echo "=========================================="
echo "[+] Iniciando servicios..."

# Matar procesos colgados en puertos 3000 y 4000
echo "[+] Limpiando puertos 3000 y 4000..."
lsof -ti:3000 | xargs kill -9 2>/dev/null
lsof -ti:4000 | xargs kill -9 2>/dev/null

# Iniciar Worker (Backend) en background
echo "[+] Iniciando Worker (Express)..."
cd worker
npm run dev > worker_output.log 2>&1 &
WORKER_PID=$!
cd ..

# Iniciar Frontend (Next.js) en foreground
echo "[+] Iniciando Dashboard (Next.js)..."
cd web
npm run dev

# Cuando se cierra el frontend (Ctrl+C), matar también el worker
kill -9 $WORKER_PID
echo "[!] FixGuard cerrado."

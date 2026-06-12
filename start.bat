@echo off
setlocal

echo ==========================================
echo     FixGuard Personal Arsenal Edition     
echo ==========================================
echo [+] Iniciando servicios...

:: Intentar matar node en los puertos 3000 y 4000 (Windows)
echo [+] Limpiando puertos 3000 y 4000...
for /f "tokens=5" %%a in ('netstat -aon ^| find ":3000" ^| find "LISTENING"') do taskkill /f /pid %%a 2>nul
for /f "tokens=5" %%a in ('netstat -aon ^| find ":4000" ^| find "LISTENING"') do taskkill /f /pid %%a 2>nul

echo [+] Iniciando Worker (Express)...
cd worker
start "FixGuard Worker" cmd /c "npm run dev"

cd ..
echo [+] Iniciando Dashboard (Next.js)...
cd web
start "FixGuard Dashboard" cmd /c "npm run dev"

echo [!] FixGuard corriendo en ventanas separadas.
echo [!] Cierra las ventanas de "FixGuard Worker" y "FixGuard Dashboard" para detenerlo.
cd ..

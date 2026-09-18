@echo off
chcp 65001 > nul
title BancoSeguro — Servidor Local
cls
echo ===================================================================
echo   🛡️  BANCO SEGURO — INICIALIZADOR DO SITE (MODO SEGURO)
echo ===================================================================
echo.
echo   Iniciando servidor local para evitar bloqueios de CORS do navegador...
echo   Seu navegador padrao sera aberto automaticamente em http://localhost:3000
echo.
echo ===================================================================
echo.

cd /d "%~dp0"
node server.js

if %errorlevel% neq 0 (
  echo.
  echo [ERRO] Nao foi possivel iniciar via Node.js.
  echo Abrindo index.html diretamente...
  start index.html
)

pause

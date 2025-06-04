@echo off
title Iniciando Sistema Flask com NGINX

REM Iniciar o Flask com Waitress
start cmd /k "python run.py"

REM Iniciar o NGINX
start cmd /k "C:\nginx\nginx.exe -c C:\nginx\conf\nginx.conf"

REM Abrir navegador automaticamente
start https://agendamentops.nuclep.gov.br:8443

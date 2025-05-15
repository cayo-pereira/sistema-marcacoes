@echo off
echo Iniciando servidor Flask...
set FLASK_APP=app.py
set FLASK_ENV=development
python -m flask run
pause

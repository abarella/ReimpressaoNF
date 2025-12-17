@echo off
REM Script batch para limpar arquivos temporarios
REM Pode ser agendado no Task Scheduler do Windows

cd /d "%~dp0"
php limpar_arquivos_temporarios.php


$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$env:PYTHONDONTWRITEBYTECODE = '1'
# 'py' is the Python launcher for Windows; 'python3' may only be the Store alias.
if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 server/main.py }
else { & python server/main.py }
exit $LASTEXITCODE

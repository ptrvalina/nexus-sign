$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
$env:PYTHONDONTWRITEBYTECODE = '1'
# 'py' is the Python launcher for Windows; 'python3' may only be the Store alias.
if (Get-Command py -ErrorAction SilentlyContinue) { & py -3 -m unittest discover -s tests -v }
else { & python -m unittest discover -s tests -v }
exit $LASTEXITCODE

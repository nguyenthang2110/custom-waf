<#
.SYNOPSIS
    Install the WAF and its ML inference service as Windows Services using NSSM.

.DESCRIPTION
    Run from an elevated (Administrator) PowerShell. Assumes the project is
    deployed to $InstallRoot, the Go binary is built at bin\waf.exe, the Python
    venv exists at .venv, and the DistilBERT model is on disk at $ModelDir.

    NSSM (the Non-Sucking Service Manager, https://nssm.cc) wraps console
    programs as proper Windows Services with auto-restart and log redirection.
    Install it first:  choco install nssm   (or unzip nssm.exe onto PATH)

.EXAMPLE
    .\install-services.ps1 -InstallRoot 'C:\waf' -ModelDir 'C:\waf\models\final_model_v7'
#>

param(
    [string]$InstallRoot = 'C:\waf',
    [string]$ModelDir    = 'C:\waf\models\final_model_v7',
    [string]$MlHost      = '127.0.0.1',
    [int]   $MlPort      = 8000
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    throw "nssm not found on PATH. Install it: choco install nssm  (or download from https://nssm.cc)"
}

$wafExe   = Join-Path $InstallRoot 'bin\waf.exe'
$uvicorn  = Join-Path $InstallRoot '.venv\Scripts\uvicorn.exe'
$mlDir    = Join-Path $InstallRoot 'ml-service'
$logDir   = Join-Path $InstallRoot 'logs'
$config   = Join-Path $InstallRoot 'configs\config.yaml'
$rules    = Join-Path $InstallRoot 'configs\rules\all_rules.json'

foreach ($p in @($wafExe, $uvicorn, $config)) {
    if (-not (Test-Path $p)) { throw "Required file missing: $p" }
}
if (-not (Test-Path $ModelDir)) { throw "ModelDir not found: $ModelDir" }
New-Item -ItemType Directory -Force -Path $logDir | Out-Null

# --- ML inference service -------------------------------------------------
Write-Host "Installing service: WAF-ML" -ForegroundColor Cyan
nssm install WAF-ML $uvicorn "app:app --host $MlHost --port $MlPort --workers 1"
nssm set WAF-ML AppDirectory $mlDir
nssm set WAF-ML AppEnvironmentExtra "MODEL_DIR=$ModelDir" "MAX_LENGTH=256" "TRANSFORMERS_OFFLINE=1" "HF_HUB_OFFLINE=1"
nssm set WAF-ML AppStdout (Join-Path $logDir 'ml-service.log')
nssm set WAF-ML AppStderr (Join-Path $logDir 'ml-service.log')
nssm set WAF-ML AppExit Default Restart
nssm set WAF-ML AppRestartDelay 5000
nssm set WAF-ML Start SERVICE_AUTO_START

# --- WAF reverse proxy ----------------------------------------------------
Write-Host "Installing service: WAF" -ForegroundColor Cyan
nssm install WAF $wafExe "-config `"$config`" -rules `"$rules`""
nssm set WAF AppDirectory $InstallRoot
nssm set WAF AppStdout (Join-Path $logDir 'waf-service.log')
nssm set WAF AppStderr (Join-Path $logDir 'waf-service.log')
nssm set WAF AppExit Default Restart
nssm set WAF AppRestartDelay 5000
nssm set WAF Start SERVICE_AUTO_START
# WAF depends on the ML service (and on Postgres, if it runs locally).
nssm set WAF DependOnService WAF-ML

Write-Host "`nStarting services..." -ForegroundColor Cyan
Start-Service WAF-ML
Start-Service WAF

Get-Service WAF-ML, WAF | Format-Table -AutoSize
Write-Host "Done. Logs: $logDir" -ForegroundColor Green
Write-Host "To remove: nssm remove WAF confirm; nssm remove WAF-ML confirm" -ForegroundColor DarkGray

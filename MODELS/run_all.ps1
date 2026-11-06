# Run the full experiment on Windows (PowerShell).
#   .\run_all.ps1           full run (sampled: 60k flows per attack, 1.2M benign)
#   .\run_all.ps1 -All      use EVERY flow of the dataset (slow, needs ~16 GB RAM)
#   .\run_all.ps1 -Quick    small test run (checks that everything works)
# Activate the virtual environment first:  .venv\Scripts\activate

param([switch]$Quick, [switch]$All)
Set-Location $PSScriptRoot

function Step([string[]]$cmd) {
    Write-Host "`n>>> python $($cmd -join ' ')" -ForegroundColor Cyan
    & python @cmd
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $($cmd -join ' ')" -ForegroundColor Red; exit 1 }
}

if ($Quick)    { Step @("preprocess.py", "--quick") }
elseif ($All)  { Step @("preprocess.py", "--all") }
else           { Step @("preprocess.py") }

foreach ($m in @("MODEL XGBOOST", "MODEL LIGHTGBM", "MODEL SW_XGBOOST", "MODEL SW_LIGHTGBM")) {
    Step @("$m\train.py")
}
if ($Quick) { Step @("MODEL LSTM\train.py", "--epochs", "2", "--samples-per-epoch", "20000") }
else        { Step @("MODEL LSTM\train.py") }

Step @("compare.py")

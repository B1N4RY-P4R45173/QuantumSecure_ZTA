# Setup for MODEL XGBOOST (run once).   .\setup.bat            or   .\setup.bat -AllData
#   1. creates/uses the shared Python environment (MODELS\.venv)
#   2. installs this model's packages (requirements.txt)
#   3. checks the NVIDIA GPU
#   4. prepares the TRUST Lab data if needed (shared by all models)
param([switch]$AllData)
. "$PSScriptRoot\..\common\setup_common.ps1"

Say "=== Setup: MODEL XGBOOST (trains on NVIDIA GPU with CUDA) ===" "Green"
Ensure-Venv
Install-Requirements "$PSScriptRoot\requirements.txt"
if (Test-NvidiaGpu) { Test-XgboostGpu }
Ensure-Data -AllData:$AllData
Say "`nSetup done. Train with:  .\train.bat" "Green"

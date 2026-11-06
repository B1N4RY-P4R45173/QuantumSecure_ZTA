# Setup for MODEL SW_LIGHTGBM (run once).   .\setup.bat            or   .\setup.bat -AllData
#   1. creates/uses the shared Python environment (MODELS\.venv)
#   2. installs this model's packages (requirements.txt)
#   3. prepares the TRUST Lab data if needed (shared by all models)
# LightGBM trains on the CPU: the pip package has no GPU support (a GPU build needs
# Visual Studio + Boost + OpenCL). LightGBM is fast on CPU, so this is fine.
param([switch]$AllData)
. "$PSScriptRoot\..\common\setup_common.ps1"

Say "=== Setup: MODEL SW_LIGHTGBM (trains on CPU) ===" "Green"
Ensure-Venv
Install-Requirements "$PSScriptRoot\requirements.txt"
Ensure-Data -AllData:$AllData
Say "`nSetup done. Train with:  .\train.bat" "Green"

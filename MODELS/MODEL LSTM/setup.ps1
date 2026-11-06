# Setup for MODEL LSTM (run once).   .\setup.bat     or   .\setup.bat -AllData     or   .\setup.bat -Cuda cu130
#   1. creates/uses the shared Python environment (MODELS\.venv)
#   2. installs PyTorch WITH CUDA (GPU build, ~2.5 GB) + this model's packages
#   3. checks that PyTorch can see the NVIDIA GPU
#   4. prepares the TRUST Lab data if needed (shared by all models)
# -Cuda: PyTorch CUDA build. cu126 works with most NVIDIA drivers; cu130/cu132 need newer drivers.
param([switch]$AllData, [string]$Cuda = "cu126")
. "$PSScriptRoot\..\common\setup_common.ps1"

Say "=== Setup: MODEL LSTM (trains on NVIDIA GPU with CUDA) ===" "Green"
Ensure-Venv
$hasGpu = Test-NvidiaGpu
if ($hasGpu) { Ensure-TorchCuda $Cuda } else { & $PY -m pip install torch }
Install-Requirements "$PSScriptRoot\requirements.txt"
Test-TorchGpu
Ensure-Data -AllData:$AllData
Say "`nSetup done. Train with:  .\train.bat" "Green"

# Shared setup functions. Each "MODEL <NAME>\setup.ps1" loads this file with:  . "$PSScriptRoot\..\common\setup_common.ps1"
# Works in Windows PowerShell 5.1 and PowerShell 7.

$ROOT = Split-Path -Parent $PSScriptRoot          # ...\MODELS
$VENV = Join-Path $ROOT ".venv"
$PY   = Join-Path $VENV "Scripts\python.exe"

function Say([string]$msg, [string]$color = "Cyan") { Write-Host $msg -ForegroundColor $color }

function Fail([string]$msg) { Write-Host "ERROR: $msg" -ForegroundColor Red; exit 1 }

function Run-Py([string[]]$pyArgs) {
    & $PY @pyArgs
    if ($LASTEXITCODE -ne 0) { Fail "python $($pyArgs -join ' ')" }
}

# 1) one shared virtual environment for all models (torch alone is ~2.5 GB, so not one per model)
function Ensure-Venv {
    if (Test-Path $PY) { Say "[1] Python environment found: $VENV"; return }
    $sys = Get-Command python -ErrorAction SilentlyContinue
    if (-not $sys) { Fail "Python not found. Install Python 3.11-3.14 from python.org (tick 'Add to PATH')." }
    Say "[1] Creating Python environment: $VENV"
    & python -m venv $VENV
    if ($LASTEXITCODE -ne 0) { Fail "could not create the virtual environment" }
    & $PY -m pip install --upgrade pip | Out-Null
}

# 2) packages for this model
function Install-Requirements([string]$reqFile) {
    Say "[2] Installing packages from $reqFile"
    & $PY -m pip install -r $reqFile
    if ($LASTEXITCODE -ne 0) { Fail "pip install failed" }
}

# 2b) PyTorch with CUDA (only the LSTM needs it). Replaces a CPU-only build if one is installed.
function Ensure-TorchCuda([string]$cuda) {
    & $PY -c "import torch, sys; sys.exit(0 if torch.version.cuda else 1)" 2>$null
    if ($LASTEXITCODE -eq 0) { Say "[2b] PyTorch with CUDA already installed"; return }
    Say "[2b] Installing PyTorch with CUDA ($cuda). Download is about 2.5 GB ..."
    & $PY -m pip uninstall -y torch 2>$null | Out-Null
    & $PY -m pip install torch --index-url "https://download.pytorch.org/whl/$cuda"
    if ($LASTEXITCODE -ne 0) { Fail "PyTorch CUDA install failed. Try another build: -Cuda cu130 or -Cuda cu132" }
}

# 3) GPU checks
function Test-NvidiaGpu {
    $smi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if (-not $smi) { Say "[3] nvidia-smi not found: no NVIDIA driver. Training will use the CPU." "Yellow"; return $false }
    $gpu = (& nvidia-smi --query-gpu=name,driver_version,memory.total --format=csv,noheader) -join "; "
    Say "[3] NVIDIA GPU: $gpu"
    return $true
}

function Test-XgboostGpu {
    $code = "import numpy as np, xgboost as x; x.XGBClassifier(n_estimators=2, device='cuda', tree_method='hist').fit(np.random.rand(200,4), np.arange(200)%2); print('XGBoost CUDA OK')"
    & $PY -c $code 2>$null
    if ($LASTEXITCODE -eq 0) { Say "    XGBoost can train on the GPU" "Green" } else { Say "    XGBoost GPU test failed -> it will train on the CPU" "Yellow" }
}

function Test-TorchGpu {
    & $PY -c "import torch; ok = torch.cuda.is_available(); print('    PyTorch', torch.__version__, '| CUDA available:', ok, '|', torch.cuda.get_device_name(0) if ok else 'no GPU')"
}

# 4) processed data (shared by all models; every model must use the SAME data)
function Ensure-Data([switch]$AllData) {
    $meta = Join-Path $ROOT "data\processed\meta.json"
    $why = ""
    if (-not (Test-Path $meta)) { $why = "no processed data yet" }
    else {
        $m = Get-Content $meta -Raw | ConvertFrom-Json
        $isAll = ($m.PSObject.Properties.Name -contains "max_flows_per_attack") -and ($null -eq $m.max_flows_per_attack)
        if ($m.quick) { $why = "current data is from --quick mode (test only)" }
        elseif ($AllData -and -not $isAll) { $why = "you asked for ALL data, current data is sampled" }
    }
    if ($why -eq "") { Say "[4] Processed data is ready ($meta)"; return }

    Say "[4] Preparing data: $why" "Yellow"
    Say "    NOTE: models trained on older data must be trained again, so all models use the same data." "Yellow"
    Push-Location $ROOT
    if ($AllData) { Run-Py @("preprocess.py", "--all") } else { Run-Py @("preprocess.py") }
    Pop-Location
}

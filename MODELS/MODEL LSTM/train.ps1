# Train MODEL LSTM on TRUST Lab and save it to output\model.pt
#   .\train.bat                          GPU (CUDA) if available, else CPU
#   .\train.bat -Device cpu              force CPU
#   .\train.bat --epochs 12 --batch 1024 extra options are passed to train.py
# Training runs on the GPU; the speed test runs on the CPU (edge gateways have no GPU).
param([string]$Device = "cuda", [Parameter(ValueFromRemainingArguments = $true)][string[]]$Extra)
. "$PSScriptRoot\..\common\setup_common.ps1"
if (-not (Test-Path $PY)) { Fail "Python environment not found. Run setup.bat first." }

$rest = @(); if ($Extra) { $rest = $Extra }
Say "=== Training MODEL LSTM (device: $Device) ===" "Green"
Push-Location $ROOT
& $PY "$PSScriptRoot\train.py" --device $Device @rest
$code = $LASTEXITCODE
Pop-Location
if ($code -eq 0) { Say "`nSaved: $PSScriptRoot\output\model.pt  (+ report.txt)" "Green" }
exit $code

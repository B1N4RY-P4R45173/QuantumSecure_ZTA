# Train MODEL LIGHTGBM on TRUST Lab and save it to output\model.txt
#   .\train.bat                      CPU (normal LightGBM has no GPU support)
#   .\train.bat --trees 600          extra options are passed to train.py
param([string]$Device = "cpu", [Parameter(ValueFromRemainingArguments = $true)][string[]]$Extra)
. "$PSScriptRoot\..\common\setup_common.ps1"
if (-not (Test-Path $PY)) { Fail "Python environment not found. Run setup.bat first." }

$rest = @(); if ($Extra) { $rest = $Extra }
Say "=== Training MODEL LIGHTGBM (device: $Device) ===" "Green"
Push-Location $ROOT
& $PY "$PSScriptRoot\train.py" --device $Device @rest
$code = $LASTEXITCODE
Pop-Location
if ($code -eq 0) { Say "`nSaved: $PSScriptRoot\output\model.txt  (+ model_info.json, report.txt)" "Green" }
exit $code

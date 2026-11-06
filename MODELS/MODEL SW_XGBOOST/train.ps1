# Train MODEL SW_XGBOOST on TRUST Lab and save it to output\model.json
#   .\train.bat                      GPU if it works, else CPU
#   .\train.bat -Device cpu          force CPU
#   .\train.bat --window 64          extra options are passed to train.py
param([string]$Device = "cuda", [Parameter(ValueFromRemainingArguments = $true)][string[]]$Extra)
. "$PSScriptRoot\..\common\setup_common.ps1"
if (-not (Test-Path $PY)) { Fail "Python environment not found. Run setup.bat first." }

$rest = @(); if ($Extra) { $rest = $Extra }
Say "=== Training MODEL SW_XGBOOST (device: $Device) ===" "Green"
Push-Location $ROOT
& $PY "$PSScriptRoot\train.py" --device $Device @rest
$code = $LASTEXITCODE
Pop-Location
if ($code -eq 0) { Say "`nSaved: $PSScriptRoot\output\model.json  (+ model_info.json, report.txt)" "Green" }
exit $code

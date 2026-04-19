$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    'C:\dev\iis-lock-fix\scripts\Start-Dashboard.ps1',
    [ref]$null,
    [ref]$errors
)
if ($errors.Count -eq 0) {
    Write-Host "OK -- 0 parse errors" -ForegroundColor Green
} else {
    foreach ($e in $errors) {
        Write-Host ("Line {0} Col {1}: {2}" -f $e.Extent.StartLineNumber, $e.Extent.StartColumnNumber, $e.Message) -ForegroundColor Red
    }
}

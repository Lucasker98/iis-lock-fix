$lines = Get-Content 'C:\dev\iis-lock-fix\scripts\Start-Dashboard.ps1'
$depth = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    # skip single-line comments and strings (rough approximation)
    $opens  = ([regex]::Matches($line, '\{')).Count
    $closes = ([regex]::Matches($line, '\}')).Count
    $depth += $opens - $closes
    if ($opens -ne $closes -or $depth -le 2) {
        Write-Host ("{0,3}: depth={1,2}  (+{2} -{3})  {4}" -f ($i+1), $depth, $opens, $closes, $line.TrimStart())
    }
}
Write-Host "Final depth: $depth"

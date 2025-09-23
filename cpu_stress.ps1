param(
    [Parameter(Mandatory=$true)]
    [int]$Percent,     # Target CPU usage percentage (0-100)
    
    [Parameter(Mandatory=$true)]
    [int]$Minutes      # Duration in minutes
)

# Get number of logical CPUs
$cpus = [Environment]::ProcessorCount

Write-Host "Starting CPU load on $cpus cores..."
Write-Host "Target: $Percent% for $Minutes minute(s)."

# Total run time in seconds
$totalTime = $Minutes * 60

# Array to store jobs
$jobs = @()

# Create workload on each CPU
for ($i=0; $i -lt $cpus; $i++) {
    $jobs += Start-Job -ScriptBlock {
        param($Percent, $totalTime)

        $start = Get-Date
        $busyFraction = $Percent / 100
        $idleFraction = (100 - $Percent) / 100

        while ((Get-Date) - $start -lt [TimeSpan]::FromSeconds($totalTime)) {
            $sw = [System.Diagnostics.Stopwatch]::StartNew()

            # Busy part
            while ($sw.Elapsed.TotalSeconds -lt $busyFraction) {
                1 + 1 | Out-Null
            }

            # Idle part
            Start-Sleep -Seconds $idleFraction
        }
    } -ArgumentList $Percent, $totalTime
}

# Wait for jobs to complete
Wait-Job $jobs
Remove-Job $jobs

Write-Host "CPU load finished."
# Loop through IPs from 1 to 254 in the 192.168.239.x range
1..254 | ForEach-Object {
    $ip = "192.168.239.$_"
    # Start a job to ping each IP asynchronously
    Start-Job -ScriptBlock {
        if (Test-Connection -ComputerName $using:ip -Count 1 -TimeoutSeconds 1 -Quiet) {
            Write-Host "$using:ip is active"
        }
    }
}

# Wait for all jobs to finish before exiting
Get-Job | Wait-Job | Receive-Job

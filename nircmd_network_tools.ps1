# nircmd_network_tools.ps1
# Useful commands using nircmd.exe for network security

# Check if nircmd.exe is in PATH
$nircmdPath = "nircmd.exe"
$found = $false

try {
    $null = Get-Command $nircmdPath -ErrorAction Stop
    $found = $true
} catch {
    $found = $false
}

if (-not $found) {
    Write-Host "nircmd.exe not found in PATH. Please enter the full path to nircmd.exe or the folder containing it:" -ForegroundColor Yellow
    $userInput = Read-Host "Full path to nircmd.exe or its folder"
    if (Test-Path $userInput) {
        if ((Get-Item $userInput).PSIsContainer) {
            # User entered a folder, check for nircmd.exe inside
            $exeCandidate = Join-Path $userInput "nircmd.exe"
            if (Test-Path $exeCandidate) {
                $nircmdPath = $exeCandidate
            } else {
                Write-Host "nircmd.exe not found in the specified folder. Exiting..." -ForegroundColor Red
                exit
            }
        } else {
            # User entered a file, check if it's nircmd.exe
            if ((Split-Path $userInput -Leaf).ToLower() -eq "nircmd.exe") {
                $nircmdPath = $userInput
            } else {
                Write-Host "The specified file is not nircmd.exe. Exiting..." -ForegroundColor Red
                exit
            }
        }
    } else {
        Write-Host "The specified path does not exist. Exiting..." -ForegroundColor Red
        exit
    }
}

while ($true) {
    Write-Host "==== Network Security Tools Menu ====" -ForegroundColor Cyan
    Write-Host "1. Capture a screenshot"
    Write-Host "2. List running processes"
    Write-Host "3. List local users"
    Write-Host "4. Internet connectivity test"
    Write-Host "5. Show message box"
    Write-Host "6. Speak success message"
    Write-Host "7. Exit"

    $choice = Read-Host "Select an option (1-7)"

    switch ($choice) {
        '1' {
            $desktopPath = [Environment]::GetFolderPath('Desktop')
            $screenshotPath = Join-Path $desktopPath "screenshot.png"
            & $nircmdPath savescreenshot $screenshotPath
            Write-Host "Screenshot saved as $screenshotPath"
        }
        '2' {
            $desktopPath = [Environment]::GetFolderPath('Desktop')
            $processFile = Join-Path $desktopPath "process_list.txt"
            tasklist > $processFile
            Write-Host "Process list saved as $processFile"
        }
        '3' {
            $desktopPath = [Environment]::GetFolderPath('Desktop')
            $userFile = Join-Path $desktopPath "user_list.txt"
            net user > $userFile
            Write-Host "User list saved as $userFile"
        }
        '4' {
            & $nircmdPath exec show cmd /c "ping 8.8.8.8"
        }
        '5' {
            & $nircmdPath infobox "Only good words for you :)"
        }
        '6' {
            & $nircmdPath speak text "Collection completed successfully!"
            Write-Host "Spoken: Collection completed successfully!"
        }
        '7' {
            Write-Host "Exiting..."
            break
        }
        default {
            Write-Host "Invalid option. Try again."
        }
    }
    if ($choice -eq '7') { break }
    Write-Host ""
}

Write-Host "Operation completed. Stay safe!" -ForegroundColor Green

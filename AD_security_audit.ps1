# ===============================
# Active Directory Security Audit
# ===============================

# Path to save the report
$ReportPath = "C:\AD_Password_Never_Expires_Report.csv"

Write-Host "===== Domain Password Policy =====" -ForegroundColor Cyan
Get-ADDefaultDomainPasswordPolicy | Format-List

Write-Host "===== Users with 'Password Never Expires' Enabled =====" -ForegroundColor Yellow
$UsersWithPasswordNeverExpires | ForEach-Object {
    $_ | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value (Get-ADUser $_.SamAccountName -Properties LastLogonDate).LastLogonDate
}

$UsersWithPasswordNeverExpires | Format-Table -AutoSize

# Save the report to CSV
$UsersWithPasswordNeverExpires | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

Write-Host "===== Auditing NTLM Usage =====" -ForegroundColor Cyan
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4624 -and $_.Properties[8].Value -eq 'NTLM' } | Format-Table -AutoSize

Write-Host "===== Disabling NetBIOS and LLMNR =====" -ForegroundColor Cyan
# Disable NetBIOS over TCP/IP
Get-NetAdapter | Set-NetAdapterBinding -ComponentID ms_netbios -Enabled $false
# Disable LLMNR
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

Write-Host "===== Checking SMB Version =====" -ForegroundColor Cyan
Get-SmbServerConfiguration | Select-Object -Property EnableSMB1Protocol, EnableSMB2Protocol

Write-Host "Report saved at: $ReportPath" -ForegroundColor Green
Write-Host "Audit completed successfully." -ForegroundColor Green

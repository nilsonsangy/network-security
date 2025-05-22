# ===============================
# Active Directory Security Audit
# ===============================

# Path to save the report
$ReportPath = "C:\AD_Password_Never_Expires_Report.csv"

Write-Host "===== Domain Password Policy =====" -ForegroundColor Cyan
Get-ADDefaultDomainPasswordPolicy | Format-List


Write-Host "===== Users with 'Password Never Expires' Enabled =====" -ForegroundColor Yellow
$UsersWithPasswordNeverExpires = Get-ADUser `
    -Filter "PasswordNeverExpires -eq $true -and Enabled -eq $true" `
    -Properties PasswordNeverExpires | 
    Select-Object Name, SamAccountName, Enabled, PasswordNeverExpires

$UsersWithPasswordNeverExpires | Format-Table -AutoSize

# Save the report to CSV
$UsersWithPasswordNeverExpires | Export-Csv -Path $ReportPath -NoTypeInformation -Encoding UTF8

Write-Host "Report saved at: $ReportPath" -ForegroundColor Green
Write-Host "Audit completed successfully." -ForegroundColor Green

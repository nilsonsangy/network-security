New-Item -Path UserAccess -ItemType Directory
New-Item -Path .\UserAccess\useraccess.psm1
New-ModuleManifest -Path .\UserAccess\useraccess.psd1 -RootModule useraccess.psm1
New-Item -Path .\UserAccess\RoleCapabilities -ItemType Directory
New-PSRoleCapabilityFile -Path .\UserAccess\RoleCapabilities\useraccessJEARole.psrc
ise .\UserAccess\RoleCapabilities\useraccessJEARole.psrc
New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer -Path .\Endpoint.pssc
ise .\Endpoint.pssc
Test-PSSessionConfigurationFile -Path .\Endpoint.pssc

$session = New-PSSESSion DomainControll
Copy-Item -Path UserAccess -Destination 'C:\Program Files\WindowsPowerShell\Modules' -Recurse -ToSession $session -Force
Copy-Item -Path .\Endpoint.pssc -Destination c:\ -ToSession $session -Force
Invoke-Command -Session $session -ScriptBlock {Register-PSSessionConfiguration -Path c:\Endpoint.pssc -Name 'UserAccess' -Force}
Enter-PSSession -ComputerName DomainControll -ConfigurationName UserAccess
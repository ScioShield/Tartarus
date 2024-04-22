# Add DNS for elastic
Add-Content 'C:\Windows\System32\Drivers\etc\hosts' "192.168.56.10 atomicfirefly-elastic"

# Unpack the archive
Expand-Archive C:\vagrant\apps\elastic-agent-8.12.0-windows-x86_64.zip -DestinationPath 'C:\Program Files\'
Expand-Archive C:\vagrant\apps\Sysmon.zip -DestinationPath 'C:\Program Files\'

# Add the defult AtomicRedTeam dir to Windows Defender Exclusions
Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"

# Install Atomic Red Team
Invoke-Expression (Invoke-WebRequest 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing);
Install-AtomicRedTeam -getAtomics

# Install the Elastic agent and Sysmon
& 'C:\Program Files\elastic-agent-8.12.0-windows-x86_64\elastic-agent.exe' install -f --url=https://atomicfirefly-elastic:8220 --certificate-authorities='C:\vagrant\certs\root_ca.crt' --enrollment-token=$(Get-Content C:\vagrant\tokens\WAEtoken.txt)
& 'C:\Program Files\Sysmon64.exe' -accepteula -i

$installer = "C:\vagrant\apps\Git-2.39.2-64-bit.exe"
$git_install_inf = "C:\vagrant\config\git.inf"
$install_args = "/SP- /VERYSILENT /SUPPRESSMSGBOXES /NOCANCEL /NORESTART /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /LOADINF=""$git_install_inf"""
Start-Process -FilePath $installer -ArgumentList $install_args -Wait

# Create the user profile script if it does not exist
$profilePath = $PROFILE
if (-not (Test-Path -Path $profilePath)) {
  New-Item -ItemType File -Path $profilePath -Force > $null
}

# Add the $env:Path update to the user's PowerShell profile
$linesToAppend = @"
`$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
Import-Module "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1" -Force
`$PSDefaultParameterValues = @{"Invoke-AtomicTest:PathToAtomicsFolder"="C:\AtomicRedTeam\atomics"}
"@

Add-Content -Path $profilePath -Value $linesToAppend

# Download and update the Sysmon config
& "C:\Program Files\Git\bin\git.exe" clone https://github.com/Neo23x0/sysmon-config.git "C:\Program Files\sysmon-config"
& Sysmon64.exe -c "C:\Program Files\sysmon-config\sysmonconfig-export.xml"
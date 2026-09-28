Clear-Host

$ScriptVersion = "20220114"
############################################################################
# This script installs the Kemp LoadMaster PowerShell Module #
############################################################################

########################
# Set common variables
$dd = Get-Date -Format yyMMdd
$dir = "$Home\Documents\temp$dd"
$output = "$dir\LoadMaster_Powershell.zip"
$start_time = Get-Date
$wait = 250
# $url = "https://kemptechnologies.com/files/packages/current/KEMP.LoadBalancer.Powershell.zip"
# $url = "https://kemptechnologies.com/krel/204/files/packages/7.2.51.0.18987-RELEASE/Kemp.LoadBalancer.Powershell.zip"
$url = "https://kemptechnologies.com/files/packages/bleeding-edge/Kemp.LoadBalancer.Powershell.zip"

########################################################
# Check to ensure script is running with elevated rights
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
Write-Host -fore red "Insufficient permissions to run this script. Open the PowerShell ISE console as an administrator and run this script again." -fore red 
pause
exit
}

#############################
# Tell user what script does

Write-Host -fore cyan "This module is installs the Kemp PowerShell module for LoadMaster for customers" 
Write-Host -fore cyan "with isolated networks.  This is Step 2 of a 2 step process."
Write-Host -fore cyan "  - Step 1 downloaded the module in .zip format." 
Write-Host -fore cyan "  - Step 2 installs the module on the management workstation." 
Write-Host -fore cyan "PRESS ENTER to continue, Crtl-C to abort " -nonewline ; read-host  

##########################################################################
# Run this script from a safe directory - setting to users home directory
if (-not (test-path $dir)) {$null = new-item -path $dir -type directory}
Set-Location -Path $dir

##############################
# Provide instructions to user
##############################

$doit = Test-Path $output
if (-not $doit) {
  do {
  write-host -fore cyan "  - Current working directory to $dir"
  write-host -fore cyan "  - Place zip file downloaded in Step 1 in this folder"
  Write-Host -fore cyan "  - Press Enter when file is in $dir" -nonewline ; read-host
  $doit = Test-Path $output
  }
  while ($doit -eq $False)
}

#############################
# Deleting old modules
Write-Host -fore cyan "  - Deleting previous installs of KEMP.LoadBalancer.Powershell module" 
remove-module -name "KEMP.LoadBalancer.Powershell" -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
remove-item -path "C:\Program Files (86)\WindowsPowerShell\Modules\KEMP.LoadBalancer.Powershell" -Force -recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
remove-item -path "C:\Program Files\WindowsPowerShell\Modules\KEMP.LoadBalancer.Powershell" -Force -recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
remove-item -path "$Home\Documents\WindowsPowerShell\Modules\KEMP.LoadBalancer.Powershell" -Force -recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
remove-item -path "C:\Windows\System32\WindowsPowerShell\Modules\KEMP.LoadBalancer.Powershell" -Force -recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

####################
# Set the path to the new KEMP Powershell module  
$ppath = ($env:PSModulePath -split ";")
if ($ppath -contains "c:\Program Files\WindowsPowerShell\Modules") {$psdir = "c:\Program Files\WindowsPowerShell\Modules"} 
else {if ($ppath -contains "c:\Program Files (x86)\WindowsPowerShell\Modules") {$psdir = "c:\Program Files (x86)\WindowsPowerShell\Modules"}}

#######################################
# Expand downloaded powershell zip file
Expand-Archive -LiteralPath $output -DestinationPath "$dir\"


########################################################
# Install associated Kemp PowerShell module Certificates
Set-Location -Path "$dir\KEMP.LoadBalancer.Powershell"

$c1 = @(dir -n *.cer)
$c2 = @(dir -n *crt)
$Crt = $c1 + $c2

if ($crt.count -gt 0) {
  Write-Host -fore cyan "  - Installing Kemp PowerShell Module related certificates"
  foreach ($c in $Crt) {
    $null = Import-Certificate -FilePath "$c" -CertStoreLocation Cert:\LocalMachine\Root
    $null = start-sleep -milliseconds $wait
    $null = Import-Certificate -FilePath "$c" -CertStoreLocation Cert:\LocalMachine\Root
    $null = start-sleep -milliseconds $wait
    $null = Import-Certificate -FilePath "$c" -CertStoreLocation Cert:\LocalMachine\TrustedPublisher
    $null = start-sleep -milliseconds $wait
  }
  Write-Host "Certificate import completed."
}

###############################################
# Cleanup any previous KEMP powershell installs
Write-Host -fore cyan "  - Removing old KEMP.LoadBalancer.Powershell modules"
$t = (get-module).Name
if ($t -contains "KEMP.LoadBalancer.Powershell") {remove-module -name "KEMP.LoadBalancer.Powershell" }
foreach ($p in $ppath) {
    if (Test-Path "$p\KEMP.LoadBalancer.Powershell") {remove-item -path "$p\KEMP.LoadBalancer.Powershell" -Force -recurse }
}

#############################################################
# Installing Kemp PowerShell modules in a system wide context

Write-Host -fore cyan "  - Installing KEMP.LoadMaster.Powershell Module"
Copy-Item -Path "$dir\KEMP.LoadBalancer.Powershell" -Destination "$psdir\" -recurse -Force
Import-Module -Name "KEMP.LoadBalancer.Powershell"
Write-Host -fore cyan "  - Module installation complete"

########################################
# Display current Kemp PowerShell module

$catch = (Get-Module -name KEMP.LoadBalancer.Powershell -InformationAction Inquire)
write-host -fore cyan "      Module Name:    "  $catch.Name
write-host -fore cyan "      Module Version: "  $catch.version


############################################
# Cleaning up installation files and folders

Write-Host -fore cyan "  - Cleaning Up Install Temp Files"
Set-Location -Path $Home
if (Test-Path "$dir") { remove-item $dir -Force -recurse }



#########################################
# Notifying user installation is complete

Write-Host -fore cyan "`nKemp Powershell Modules are now fulling installed and enabled"



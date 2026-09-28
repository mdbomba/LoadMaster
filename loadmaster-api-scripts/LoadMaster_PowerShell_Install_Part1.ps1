Clear-Host

$ScriptVersion = "20220114"
###############################################################
# This script downloads the Kemp LoadMaster PowerShell Module #
###############################################################


########################
# Set common variables
$dd = Get-Date -Format yyMMdd
$dir = "$Home\Documents\temp$dd"
$zipname = "LoadMaster_PowerShell.zip"
$url = "https://kemptechnologies.com/files/packages/bleeding-edge/Kemp.LoadBalancer.Powershell.zip"
$output = "$dir" + "\" + "$zipname"

##########################################################################
# Run this script from a safe directory - setting to users home directory
if (-not (test-path $dir)) {$null = new-item -path $dir -type directory}
Set-Location -Path $dir

#############################
# Tell user what script does

Write-Host -fore cyan "This module is designed to install the Kemp PowerShell module for LoadMaster " 
Write-Host -fore cyan "for customers with isolated networks. This is Step 1 of a 2 step process. " 
Write-Host -fore cyan "  - Step 1 downloads the module in .zip format."
Write-Host -fore cyan "  - Step 2 installs the module on the management workstation." 
Write-Host -fore cyan "If you want to continue - press enter. To cancel press Crtl-C. " -nonewline ;read-host  

##########################
# Clear previous downloads
##########################
remove-item -path "$output" -Force -recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue

######################################################
# Download Kemp Powershell and save as Powershell.zip
$catch = curl -Method get $url -OutFile $zipname

Write-Host -fore cyan "Download of Kemp PowerShell Module complete."
Write-Host -fore cyan "File located at : " -nonewline ; write-host -fore yellow  "$output"
Write-Host -fore cyan "`nCopy zip file to removeable media and move to your management workstation."
Write-Host -fore cyan "After zip file is placed on management workstation, run part 2 powershell script "
Write-Host -fore yellow "LoadMaster_PowerShell_Install_Part2.ps1" -nonewline ; write-host -fore cyan " as Administrator on management workstation."


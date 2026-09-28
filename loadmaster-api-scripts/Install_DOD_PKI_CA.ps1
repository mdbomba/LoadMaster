$ScriptVersion = "20200921"        # Included certificates current as of 9/21/2020

################################################################################################################
# This script installs DoD Root and Intermediate Certificates to all LoadMasters                               #
#    - Please run this script from a folder that contains all certificates in PEM (Base64) Format              #
#    - Folder also needs an input file $LM_File containing IP addresses for LoadMaster management interfaces   #
################################################################################################################
Clear-Host
write-host -fore cyan "###########################################################################################################"
write-host -fore cyan "# This script installs DoD Root and Intermediate Certificates to all LoadMasters                          #"
write-host -fore cyan "#    - Please run this script from a folder that contains all certificates in PEM (Base64) Format         #"
write-host -fore cyan "#    - Folder also needs an input file containing IP addresses for LoadMaster management interfaces       #"
write-host -fore cyan "#                                                                                                         #"
write-host -fore cyan "# You need to edit this script to configure variables for admin account/password and IP address filename  #"
write-host -fore cyan "# before running this script                                                                              #"
write-host -fore cyan "###########################################################################################################"
write-host -fore cyan "Do you want to continue to execute this script (Y/N): " -NoNewline
$YN = read-host
if ($YN -match "^N") {exit}

#######################################################################################
#             CONFIGURE VARIABLES - CHANGE BELOW TO MATCH YOUR ENVIRONMENT            #
#######################################################################################
$KempAdmin = "admin"
$KempPassword = Read-Host -Prompt "Enter password for $KempAdmin" -AsSecureString
$LM_File = ".\LoadMasterIP.txt"
$ScriptHome = "C:\ScriptHome"
#######################################################################################
#                               ALL VARIABLES CONFIGURED                              #
#######################################################################################

########################################
# Standardized variables - Do not edit #
########################################
$IP = $null
$IP = New-Object System.Collections.Generic.List[System.Object]
$s = $null
$s = New-Object System.Collections.Generic.List[System.Object]
$CertList = $null
$CertList = New-Object System.Collections.Generic.List[System.Object]

$pattern1 = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
$pattern2 = '\.cer$'
$pattern3 = 'RCA.\.cer$'

##############################################################################
# Read file and extract individual lines that are in IP address or FQDN format
##############################################################################
set-location -path $ScriptHome

###################################
# Check for LoadMasterIP.txt file #
###################################
if (-Not (Test-Path "$LM_File")) {
Write-Host -fore red "`nTerminating Script - LoadMaster IP list file not found ($LM_File)"
start-sleep -milliseconds 3000
exit 
}

#############################################
# Loading LoadMaster IP addresses from File #
#############################################
$in = @(Get-Content -Path $LM_File)
foreach ($item in $in) { if ($item -match $pattern1) {$S += $item}  }

###########################################################################################
# Sanity Check - if no LoadMaster IP addresses are extracted from File - terminate script #
###########################################################################################
if ($S.count -eq 0) { 
Write-Host -fore red "`nERROR - SCRIPT TERMINATING - No LoadMaster IP addresses identified."
start-sleep -milliseconds 3000
exit 
}

###############################
# Create a list of cert files #
###############################
Get-ChildItem -Name -Path "dod*.cer" > .\certlist.txt
$CertList = @(Get-Content -Path ".\certlist.txt")

############################################################
# Sanity Check - If no .cer files found - terminate script #
############################################################
if ($CertList.count -eq 0) {
Write-Host -fore red "`nERROR - SCRIPT TERMINATING - No .cer files located in $ScriptHome."
start-sleep -milliseconds 3000
exit
}

################################
# Loop through all LoadMasters #
################################

##################################
# Create secure login credential #
##################################
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $KempAdmin, $KempPassword



###################################################################################################################################
#                                             Step thru all LoadMAster IP addresses and Install Certificates                      #
###################################################################################################################################

foreach ($IP in $S) {
write-host -fore cyan "`nInstalling DoD PKI Root and Intermediate Certificates to LoadMaster - $IP"

#######################
# Login to Loadmaster #
#######################

$Login = Initialize-LmConnectionParameters -Address $IP -LBPort 443 -Credential $cred

###############################################
# Verify successful login or terminate script #
###############################################
$lma = Get-LmParameter -param version
$Test = $LMA.ReturnCode -match "200"
if ($Test) {
Write-Host -fore green "`n  -  LoadMaster credentials validated`n" 
} 
else {
Write-Host -fore red "`nScript Terminating - LoadMaster credentials failed validation for IP address - $IP"
start-sleep -milliseconds 3000
exit
}


#####################################
# Install Intermediate Certificates #
#####################################

foreach ($CertFile in $CertList) {

$CertName = $CertFile.split('.')[0].TrimStart("dod")

Write-Host -fore green "  -  Installing $CertFile as $CertName"

$catch = New-TlsIntermediateCertificate -Name $CertName -Path $CertFile

start-sleep -milliseconds 1200

}

}
write-host ""
write-host -fore Green "##################################################################"
write-host -fore Green "#                                                                #"
write-host -fore Green "#   DOD PKI Root and Intermediate Certificate Import Completed   #"
write-host -fore Green "#                                                                #"
write-host -fore Green "##################################################################"

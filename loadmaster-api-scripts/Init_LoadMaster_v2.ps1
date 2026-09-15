#######################################################################################################
## This script uploads and assigns certificates to the LoadMaster management interface (WUI and API) ##
#######################################################################################################

###########################
# Describe what script does
###########################
Clear-Host
Write-Host -fore Cyan "The purpose of this script is to:"
Write-Host -fore white "  -  install certificates to LoadMaster"
Write-Host -fore white "  -  create a custom cipher set based on FIPS minus 3DES"
Write-Host -fore white "  -  assign uploaded certificate to LoadMaster management interface"
Write-Host -fore white "  -  assign custom cipher set to LoadMaster management interface"
Write-Host -fore Cyan "`nRun this script from a folder where you have downloaded certificates:"
Write-Host -Fore White "  -  Web server certificate in .pem or .pfx format"
Write-Host -Fore White "  -  Issuing CA certificate in base64 format"
Write-Host -Fore White "  -  Root CA certificate in base64 format"

Write-Host -fore Cyan "`nPress enter to continue or Ctrl-C to abort"
pause

####################################################################################
# Set wait state between commands (increase if script generates errors when running)
####################################################################################
$wait = 250 

###############################################################
# Nested loops to ask for IP address, verify is proper format
# Validate IP address format and IP address is reachable
###############################################################
$pattern = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
Write-Host -fore Cyan "`nLOADMASTER HOST INFORMATION INPUT`n"
do {

  $ip = Read-Host 'Enter LoadMaster Management IP address (x.x.x.x)'
  $ok1 = $ip -match $pattern																# Pattern match to ensure IP address is properly formatted
    if ($ok1) {
    Write-Host -fore Green "IP address entered in correct format. IP = $ip"
    $ok2 = test-connection $ip -quiet -count 1 												# Ping test to see if something is listening to IP address
      if ($ok2) {
      Write-Host -fore green "IP address $IP is reachable over the network`n"
      }
      else { Write-Host -fore Red "IP address $ip is NOT reachable over the network" }
    }
    else { Write-Host -fore red "IP address entered in incorrect format. Data entered was $ip" ; $ok2 = $false }
  if ($ok1 -and $ok2) {$ok = $true} else {$ok = $false}
 
  if ($ok -eq $false) { Write-Host -fore Red -back White "`nTRY AGAIN!`n" }
} until ( $ok )
$LM_IP = $ip	

##################################################################
# Determine necessary construct to send API commands to LoadMaster
# FQDN or IP Address
##################################################################
$ok = $FALSE
do {
$t1 = Read-Host "Does the Amin Cert use the LoadMaster FQDN as the Common Name (Y/N)"
$Do_FQDN = ($t1 -match "Y|y")
if ($t1 -match "Y|y" -or $t1 -match "N|n") {$ok = $true}
} until ($ok)

$fqdn = ""
if ($Do_FQDN) {
$fqdn = Read-host 'Enter FQDN used for Admin Cert'
}
else {$fqdn = $LM_IP}

#######################################
# Collect LoadMaster Admin credentials
#######################################
write-host -fore Cyan "`nLOADMASTER ADMIN CREDENTIALS INPUT`n"
$KempAdmin = Read-Host -Prompt "Enter your LoadMaster administrator account name"
$SecureString = Read-Host -Prompt "Enter the password for the Admin account" -AsSecureString

############################
# Set Certificates to import
############################
write-host -fore Cyan "`nLOADMASTER CERTIFICATE INPUT`n"
$Certfile = $NULL
do {$CertFile = Read-Host -Prompt "Admin Cert - Enter the path to Admin certificate (pem/pfx)" } while (-Not (Test-Path "$CertFile"))
$securedValue = Read-Host -Prompt "Admin Cert - Enter the password for Admin certificate" -AsSecureString
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securedValue)
$CertPass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
$CertName = Read-Host -Prompt "Admin Cert - Enter a name to assign to the certificate"

$ICA_File = ""
$Do_ICA = $True
Write-Host "`nIf the Admin certificate is not a self signed certificate, then complete this section"
$ICA_File = Read-Host -Prompt "Issuing CA Cert - Enter the path to cer file (base64 encoded) or Enter for none" 
if (-NOT $ICA_File -eq "") {$ICA_Name = Read-Host -Prompt "Issuing CA Cert - Enter a name to assign to the certificate"}
else {$Do_ICA = $False}

$CA_File = ""
$Do_CA = $True
Write-Host "`nIf the issuing CA is not the Root CA, then complete this section"
$CA_File = Read-Host -Prompt "Root CA Cert - Enter the path to cer file (base64 encoded) or Enter for none" 
if (-NOT $CA_File -eq "") {$CA_Name = Read-Host -Prompt "Root CA Cert - Enter a name to assign to the certificate"}
else {$Do_CA = $False}



##############
# Create Login
##############
$cred = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $KempAdmin, $SecureString
$Login = Initialize-LmConnectionParameters -Address $LM_IP -LBPort 443 -Credential $cred

######################
# Install Certificates
######################
Write-Host -fore Cyan "`nInstalling LoadMaster management certificates"

$catch = New-TlsCertificate -Name $CertName -Password $CertPass -Path $CertFile
if ($?) {Write-Host -fore green "Completed installation of Admin Cert: $CertFile"} 
else {Write-Host -fore red "Failed installation of ADmin Cert: $CertFile"}
start-sleep -milliseconds $wait

if ($Do_ICA) {
$catch = New-TlsIntermediateCertificate -Name $ICA_Name -Path $ICA_File
if ($?) {Write-Host -fore green "Completed installation of Issuing CA Cert: $ICA_File"} 
else {Write-Host -fore red "Failed installation of Issuing CA Cert: $ICA_File"}
start-sleep -milliseconds $wait
}

if ($Do_CA) {
$catch = New-TlsIntermediateCertificate -Name $CA_Name -Path $CA_File
if ($?) {Write-Host -fore green "Completed installation of Root CA Cert: $CA_File"} 
else {Write-Host -fore red "Failed installation of Root CA Cert: $CA_File"}
start-sleep -milliseconds $wait
}

############################
# Enable Certificate for WUI
############################
Write-Host -fore Cyan "`nAssigning LoadMaster management certificates (used for WUI and API)"

$catch = Set-SecAdminWuiConfiguration -CertificateStoreLocation $certname
if ($catch.returncode -eq "200") { Write-Host -fore green "Completed assignment of Admin Cert: $certname" } 
else { Write-Host -fore red "Failed assignment of Admin Cert: $certname" }

##########################
# Create custom cipher set
##########################
Write-Host -fore Cyan "`nCreating FIPS-DES Cipher set."
$catch = Set-TlsCipherSet -Name FIPS-DES -Value "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:AES256-GCM-SHA384:AES256-SHA256:AES256-SHA:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:AES128-GCM-SHA256:AES128-SHA256:AES128-SHA"
$catch = Get-TlsCipherSet -Name FIPS-DES
if (-NOT ($catch.returncode -eq "200")) { Write-Host -fore red "`n`nCREATION OF CUSTOM CIPHER SET FAILED" }
else  { Write-Host -fore green "Creation of custom cipher set was successful"

##########################
# Assign Custom Cipher Set    # Needed to use direct API command as powershell command does not currently support custom cipher sets 
##########################

######################################################################
# Test to see if LoadMaster certificate is based on FQDN or IP Address
######################################################################
$Results = Invoke-WebRequest  -Credential $cred  -uri "https://$fqdn/access/get?Param=serialnumber"
if (-NOT $?) {$fqdn = $LM_IP}
$Results = Invoke-WebRequest  -Credential $cred  -uri "https://$fqdn/access/get?Param=serialnumber"
if (-NOT $?) {
Write-Host -fore red "`n`nSCRIPT CANNOT ASSIGN CUSTOM CIPHER SET TO LOADMASTER WUI"}

#################################
# Assign custom cipher set to WUI
#################################
else {$Results = Invoke-WebRequest  -Credential $cred  -uri "https://$fqdn/access/set?Param=WUICipherset&Value=FIPS-DES"
if ($?) {Write-Host -fore green "Assignment of custom cipher set completed"}
}
}
######################
# Clear all variables
######################

$wait = $NULL
$pattern = $NULL
$ip = $NULL
$LM_IP = $NULL
$KempAdmin = $NULL
$KempPassword = $NULL
$Certfile = $NULL
$CertPass = $NULL
$CertName = $NULL
$CA_File = $NULL
$CA_Name = $NULL
$SecureString = $NULL
$SecureString2 = $NULL
$cred = $NULL
$Login = $NULL
$bstr = $NULL
$securedValue = $NULL
$fqdn = $NULL

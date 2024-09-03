clear-history
clear-host
$ScriptVersion = "v1.2.20240715"
$scripthome = ($pwd).path

#Fixes
# Added logic to prompt for missing parameters
# Enabled script to work on LoadMaster HA pairs
# Added Disable SSL Renegotiation 
# Added checks for existing services configurations and skip if already configured
# Added logic for no entry on prompts
# Added kerberos encryption requirements 
# Created custom cipher set FIPS++ to remove DHE-, 3DES and SHA1
# Applied FIPS++ cipher set to management traffic
# Fix various logic errors
# Automated assignment of management certificates based on SAN IPv4 Addresses

#REQUIREMENTS
# 0. Script must be run in an admin elevated powershell
# 1. Script will be ran from what ever directory you are in when you start the script ($scripthome)
# 2. Optional text file containing all LoadMaster management interface IP addresses.
# 3. Optional management certificates in .pfx format (located in $scripthome directory)
# 4. Optional intermediate certificates in .cer (base64) format (located in $scripthome directory)
# 5. You will also need a common local admin account and password for all LoadMaster appliances. "bal" account can be used for 
#    this purpose, but all LoadMaster appliances need to use same local admin account and password.

#############################
# Wait timer between commands 
#############################
$wait = 250                                        ## Recommend you leave this value as is. 
$db = $False                                       ## This sets debug on or off for additional messages

#################
# Create Log File                                  ## DO NOT UPDATE THIS SECTION
#################
$dd = Get-Date -Format yyMMddhhmmss             ## Get a date time indel to prepend to file name
$logfile = "Kemp_LoadMaster_STIG_"+$dd+".log"        ## Create a unique log file name including datetime 
if (test-path -path $logfile) {del $logfile}
add-content -path $logfile -Value "Log file for STIG Script`nVersion Number = $ScriptVersion"

#########################################################################################################################
#                                               START CONFIGURING VARIABLES
#########################################################################################################################

#########################
# Warning Banner Messages
#########################
[string]$ConsoleMsg = "WARNING - YOU ARE ACCESSING A UNITED STATES GOVERNMENT (USG) INFORMATION SYSTEM PROVIDED FOR AUTHORIZED USE ONLY. Communications using or data stored on this Information System is not private. Upon proper legal request related data will be released for personnel misconduct and law enforcement purposes. Unauthorized use of this system will be prosecuted. By continuing to login, you agree to the above terms and conditions."
[string]$WUIMsg = "<!DOCTYPE html><html><head><title>USG Warning Banner</title></head><style>p {color: black;}.title1 {font-size: 13px;text-align: center;}.paragraph1 {font-size: 12px; text-align: left;}</style><h1>USG WARNING AND CONSENT BANNER</h1><hr><p class=title1>YOU ARE ACCESSING A UNITED STATES GOVERNMENT (USG) INFORMATION SYSTEM<br>PROVIDED FOR AUTHORIZED USE ONLY</p><br><p class=paragraph1>By using this Information System (which includes any device attached to this Information System), you consent to the following conditions:<br><br>- USG routinely intercepts and monitors communications on this Information System for purposes including, but not limited to, penetration testing, network operations and defense, and upon proper legal request for personnel misconduct and law enforcement purposes.<br><br>- At any time, the USG may inspect and seize data stored on this Information System. Communications using, or data stored on this Information System are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any authorized purpose. This Information System includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.<br><br> - Notwithstanding the above, using this Information System does not constitute consent to legal or criminal investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. <br><br> - USG requires all USG personnel to complete Information System Security training annually.<br><br>- By continuing to login, you agree to the above terms and conditions.</p></body></html>"

#####################
# LoadMaster settings
#####################
$LM_IP = "10.0.0.15"                        ## UPDATE - If left blank "", script will prompt for value (IP address(s) or filename)
$LM_Port = "443"                            ## UPDATE - If left blank "", script will prompt for value (443 or 8443 for Azure or AWS)
$LM_Prefix = "vlm"                          ## UPDATE - If left blank "", script will prompt for prefix and append last IP octet to create hostname
$LM_Name = ""                               ## UPDATE - If left blank "", script will prompt for value (hostname)
$LM_AdminGW = "10.0.0.2"                    ## UPDATE - If left blank "", admin gateway will be set to default gateway
$LM_Admin = "bal"                           ## UPDATE - If left blank "", script will prompt for value
$LM_AdminPass = "Kemp1fourall"              ## UPDATE - If left blank "", script will prompt for value 


###############
# LDAP SETTINGS                             
###############
$LDAP_Name = ""                             ## UPDATE - If left blank (""), then LDAP will not be provisioned
$LDAP_Servers = ""                          ## UPDATE - If left blank (""), then LDAP will not be provisioned
$LDAP_Domain ="" 		                    ## UPDATE - If left blank (""), then LDAP will not be provisioned
$LDAP_Protocol = ""                         ## UPDATE - Protocol to connect to LDAP Server (Unencrypted or LDAPS)
$LDAP_Port = 389                            ## UPDATE - Port to connect to LDAP Server (389 for Unencrypted or 636 for LDAPS)
$LDAP_User = ""                             ## UPDATE - Account used to bind to LDAP server
$LDAP_UserPass = ""                         ## UPDATE - If left blank (""), then this will be prompted for later in script

######################
# User Accout Creation                      
######################
$LM_CertUser = "mike@kemptech.biz"          ## UPDATE - If left blank (""), then cert user will not be provisioned
$LDAP_Group = "loadmaster"                            ## UPDATE - If left blank (""), then WUI LDAP will not be provisioned
$LM_User = "adminmike"                               ## UPDATE - If left blank (""), then admin user will not be provisioned
$LM_UserPass = "Kemp1fourall"                           ## UPDATE - If left blank (""), then this will be prompted for later in script

##############
# NTP Settings                              
##############
$NTP_Name = "time.nist.gov"                 ## UPDATE - If left blank (""), then NTP will not be enabled
$NTPV3 = $False                             ## UPDATE - If using NTPv3, set to $True, otherise set to $False
$NTPV3_Keytype = ""                         ## UPDATE - If using NTPv3, ENTER a valid values (SHA or MD5)
$NTPV3_KeyNum = ""                          ## UPDATE - If using NTPv3, ENTER a Valid value (1 - 99)
$NTPV3_Secret = ""                          ## UPDATE - If using NTPv3, ENTER a valid Secret associated to specific NTPv3_KeyNum

#######################
# CERTIFICATES SETTINGS
#######################
$doCER = $True                              ## UPDATE - If set to true, script will attempt to install intermediate certificates
$doPFX = $True                              ## UPDATE - If set to true, script will attempt to install administrative certificates


#########################################################################################################################
#                                               END CONFIGURE VARIABLES
#########################################################################################################################

################################
# Preload settings into log file
################################


$msg = "###############################################`nScript to apply STIG/SRG settings to LoadMaster" ; add-content -path $logfile -value $msg
$msg = "###############################################`nDate-Time Script was ran = " + $dd ; add-content -path $logfile -value $msg
$msg = "`n##### PARAMETERS REPORT ####" ;  add-content -path $logfile -value $msg
$msg = "Debug ---------------------- " + '$db'            + " = " + $db ; add-content -path $logfile -value $msg
$msg = "Pause between api commands - " + '$wait'          + " = " + $wait ; add-content -path $logfile -value $msg
$msg = "LDAP Service Name ---------- " + '$LDAP_Name'     + " = " + $LDAP_Name ; add-content -path $logfile -value $msg
$msg = "LDAP Server Names ---------- " + '$LDAP_Servers'  + " = " + $LDAP_Servers ; add-content -path $logfile -value $msg
$msg = "LDAP Domain ---------------- " + '$LDAP_Domain'   + " = " + $LDAP_Domain ; add-content -path $logfile -value $msg
$msg = "LDAP Protocol -------------- " + '$LDAP_Protocol' + " = " + $LDAP_Protocol ; add-content -path $logfile -value $msg
$msg = "LDAP Port ------------------ " + '$LDAP_Port'     + " = " + $LDAP_Port ; add-content -path $logfile -value $msg
$msg = "LDAD Service Account ------- " + '$LDAP_Admin'    + " = " + $LDAP_Name ; add-content -path $logfile -value $msg
$msg = "LDAP Service Account Pass--- " + '$LDAP_UserPass' + " = " + $LDAP_UserPass ; add-content -path $logfile -value $msg
$msg = "LDAP Service Name ---------- " + '$LDAP_Name'     + " = " + $LDAP_Name ; add-content -path $logfile -value $msg
$msg = "LDAP Admin Group Name ------ " + '$LDAP_Group'    + " = " + $LDAP_Group ; add-content -path $logfile -value $msg
$msg = "LM Cert Admin User Name ---- " + '$LM_CertUser'   + " = " + $LM_CertUser ; add-content -path $logfile -value $msg
$msg = "LM Password Admin User Name- " + '$LM_User'       + " = " + $LM_User ; add-content -path $logfile -value $msg
$msg = "LM Password Admin User Pass -" + '$LM_UserPass'   + " = " + $LM_UserPass ; add-content -path $logfile -value $msg
$msg = "NTP Server List ------------ " + '$NTP_Name'      + " = " + $NTP_Name ; add-content -path $logfile -value $msg
$msg = "NTP Protocol Version ------- " + '$NTPV3'         + " = " + $NTPV3 ; add-content -path $logfile -value $msg
$msg = "NTPv3 KeyType -------------- " + '$NTPV3_Keytype' + " = " + $NTPV3_Keytype ; add-content -path $logfile -value $msg
$msg = "NTPv3 Key Number ----------- " + '$NTPV3_KeyNum'  + " = " + $NTPV3_KeyNum ; add-content -path $logfile -value $msg
$msg = "NTPv3 Key Number Secret ---- " + '$NTPV3_Secret'  + " = " + $NTPV3_Secret  ; add-content -path $logfile -value $msg
$msg = "Install Intermediate Certs - " + '$doCER'         + " = " + $doCer ; add-content -path $logfile -value $msg
$msg = "Install TLS Certificates --- " + '$doPFX'         + " = " + $doPFX ; add-content -path $logfile -value $msg



#####################################
# CREATE FUNCTION TO SET PARAMETERS
#####################################
function Set-STIGParameter ($param, $paramvalue) {
  $doit = ((Get-LmParameter -LoadBalancer $ip -Param $param).data.$param -ne $paramvalue)
  if ($doit) {
    $catch = (Set-LmParameter -LoadBalancer $ip -Param $param -Value $paramvalue).ReturnCode
    $msg = "$catch  - LoadMaster parameter $param set to $paramvalue" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
    start-sleep -Milliseconds 300
  }
  Else {$msg = "200  - Skipping - LoadMaster parameter $param already set to $paramvalue" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
}

######################################################################
# Provide info on script and an option to continue or terminate script
######################################################################
write-host -fore cyan "SCRIPT TO APPLY DOD SECURITY SETTINGS TO LOADMASTER"
#$catch = start-sleep -milliseconds 1000
#write-host -fore cyan "To run this script, you will need the admin account and password for the LoadMaster."
#write-host -fore cyan "Before running this script, you need to set configuration variables inside the script."
#write-host -fore green "Enter Y to continue, any other key to terminate" -NoNewline ; $YN = read-host " "
#if (-NOT ($YN -match "^Y")) {exit}

#########################################################################################################################
#                                           DO NOT MODIFY SETTINGS BELOW THIS LINE
#########################################################################################################################

#####################################################
#Check for Kemp Powershell Build minimum requirements
#####################################################
$PP = import-module KEMP.LoadBalancer.Powershell
$PS_Required = "7.2.48.0"
$PS_R3 = ($PS_Required.Split("."))[2]
$PS_Version = $Null
$PS_Version = (Get-Module -name KEMP.LoadBalancer.Powershell).Version
if ($PS_Version -eq $Null) {$msg = "TERMINATING SCRIPT - Incorrect Kemp PowerShell Module not installed. Install module and rerun script. Press enter to continue: " ; add-content -path $logfile -Value $msg ; write-host -fore red $msg -NoNewline ; read-host ; exit }   
if ($PS_Version.Build -lt $PS_R3) {$msg = "TERMINATING SCRIPT - Incorrect Kemp PowerShell Module Installed. Press enter to continue: " ; add-content -path $logfile -Value $msg ; write-host -fore red $msg -NoNewline ; read-host ; exit }
$msg = "Kemp PowerShell Module   --- " + 'PowerShell Module'         + " = " + $PS_Version ; add-content -path $logfile -value $msg


###########################
# Declare working variables
###########################
[string]$ip = $null
[array]$in = $null
[array]$s = $null
[array]$ss = $null
[array]$n = $null
[array]$nn = $null
[array]$c = $null
[array]$cc = $null
[string]$pattern1 = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
[string]$pattern2 = '\.txt$'

############################
# Determine processes to run
############################
[bool]$doNTP = ($NTP_Name -ne "")
[bool]$doNTPv3 = (($NTPV3_Keytype -ne "") -AND ($NTPV3_KeyNum -ne "") -AND ($NTPV3_Secret -ne "") -AND ($NTPv3 -ne $false))
[bool]$doLDAP = (($LDAP_Name -ne "") -and ($LDAP_Servers -ne "") -and ($LDAP_Domain -ne ""))
[bool]$doWUILDAP = ($LDAP_Group -ne "")
[bool]$doLMUser = ($LM_User -ne "")
[bool]$doCertUser = ($LM_CertUser -ne "")
[bool]$doIP = ($LM_IP -match $pattern1)
[bool]$getIP = ($LM_IP -eq "")
[bool]$doIPFile = (-not $getIP -and (Test-Path -path "$scripthome\$LM_IP" -PathType Leaf))
#if ($doIPFile -and ($LM_Prefix -eq "")) {[string]$LP_Prefix = read-host -Prompt "Enter Prefix for auto assignment of hostname (prefix + Last IP Octet) (e.g. vlm)"}
#if ($doIPFile -and ($LM_Prefix -eq "")) {[bool]$doName = $False} Else {[bool]$doName = $True}

############################
# Prompt for misssing values
############################
## Port
do { if (($LM_Port -ne "443") -and ($LM_Port -ne "8443")) {write-host -fore green -nonewline "Enter LoadMaster admin port (443/8443): " ; $LM_Port = Read-Host } }
until (($LM_Port -eq "443") -or ($LM_Port -eq "8443"))
## LM_Prefix
do { if ($LM_Prefix -eq "") {write-host -nonewline -fore green "Enter prefix to auto generate LoadMaster hostname: "; $LM_Prefix = read-host } }
until ($LM_Prefix -ne "")


#############################
# Get LoadMaster IP addresses
#############################
[array]$s = $Null ; [array]$n = $Null ; [array]$in = $Null ; [string]$item = $Null
#Process filename if provided
if ($doIP) {
  $in = $LM_IP
  if ($in.length -gt 0) {foreach ($item in $in) {if ($item -match $pattern1) {$s += $item ; $n += ($LM_Prefix + $item.split('.')[-1])}} }
}

if ($doIPFile) {
  $in = @(Get-Content -Path $LM_IP)
  if ($in.length -gt 0) {foreach ($item in $in) {if ($item -match $pattern1) {$s += $item ; $n += ($LM_Prefix + $item.split('.')[-1])}} }
}

# Prompt for IP address if filename not provided or filename load fails
if ($s.count -eq 0) {
  $s = $Null ; $n = $Null ; $in = $Null
    do {
      $in = (read-host -Prompt "Enter IP address for LoadMaster(s), press enter on empty line to end input")
      if ($in -match $pattern1) {$s += $item ; $n += ($LM_Prefix + $item.split('.')[-1])} 
    }
    while (($in -ne "") -or ($s.count -eq 0))
  }

$msg = "LoadMaster Management IP --- " + '$LM_IP'         + " = " + $s ; add-content -path $logfile -value $msg
$msg = "LoadMaster Management Port - " + '$LM_Port'       + " = " + $LM_Port ; add-content -path $logfile -value $msg
$msg = "LoadMaster Naming Prefix --- " + '$LM_Prefix'     + " = " + $LM_Prefix ; add-content -path $logfile -value $msg
$msg = "LoadMaster Name ------------ " + '$LM_Name'       + " = " + $LM_Name ; add-content -path $logfile -value $msg
$msg = "LoadMaster Admin GW--------- " + '$LM_AdminGW'    + " = " + $LM_AdminGW ; add-content -path $logfile -value $msg
$msg = "LoadMaster Admin Name ------ " + '$LM_Admin'      + " = " + $LM_Admin ; add-content -path $logfile -value $msg
$msg = "LoadMaster Admin Passwd ---- " + '$LM_AdminPass'  + " = " + "###########" ; add-content -path $logfile -value $msg
$msg = "##### PARAMETERS REPORT ####`n" ;  add-content -path $logfile -value $msg
$msg = "##### EXECUTION REPORT ####" ;  add-content -path $logfile -value $msg

###############################
# Create a list of cert files #
###############################
if ($DoCER) {
  [array]$CertList = $null
 # if (test-path -Path ".\Certificates") {$cer = (Get-ChildItem  -Path ".\Certificates" -Name "*.cer")}
 # $cer = $cer + (Get-ChildItem  -Path "." -Name "*.crt")
 # foreach ($c in $cer) {$certlist = $certlist + "$scripthome\Certificates\$c"}
  $cer = (Get-ChildItem  -Path "." -Name "*.cer")
  $cer = $cer + (Get-ChildItem  -Path "." -Name "*.crt")
  foreach ($c in $cer) {$certlist = $certlist + "$scripthome\$c"}  
  if ($CertList.count -gt 0) {$DoCER = $True} Else {$DoCER = $False ; $DoCertUser = $False}
  $msg = "200  - CER or CRT files found = $DoCER"
  if ($db) {write-host -fore cyan "$msg"}
  add-content -path $logfile -Value $msg
}

##############################
# Create a list of pfx files #
##############################
if ($DoPFX) {
  [array]$pfxList = $null
 # if (test-path -Path ".\Certificates")  {$pfx = (Get-ChildItem  -Path ".\Certificates" -Name "*.pfx")}
 # foreach ($p in $pfx) {$pfxlist = $pfxlist + "$scripthome\Certificates\$p"}
  $pfx = (Get-ChildItem  -Path "." -Name "*.pfx")
  foreach ($p in $pfx) {$pfxlist = $pfxlist + "$scripthome\$p"}
  if ($pfxList.count -gt 0) {$doPFX = $True} Else {$doPFX = $False}
  if ($db) { $msg = "PFX files found = $doPFX" ; write-host -fore cyan "$msg" ; add-content -path $logfile -Value $msg}
}

#############################################
# Test connectivity and adjust list as needed
#############################################
[array]$ss = $null; [array]$nn = $null; [array]$cc = $null ; [int]$i = $Null
if ($db) {write-host -fore cyan "`nTesting connectivity to all LoadMasters on port $LM_Port"}
for ($i=0; $i -lt $S.Count; $i++) { $ip = $s[$i] ; $uri = "https://" + $ip + ":" + $LM_Port
  $ok = try {curl -TimeoutSec 1 $uri -ErrorVariable ok1 -ErrorAction SilentlyContinue 2>$null} catch {"400"}
  if ($ok -eq "400") {$ok = $False} Else {$ok = $True}
  if ($ok) {$ss = $ss + $S[$i] ; $nn = $nn + $n[$i]}
  if ($ok) {$msg = "200 - Pass Connection test - $ip" + ":" +"$Port" ;  ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg}
  if (-not $ok) {$msg = "500 - Failed Connection test - $ip $LM_Port" ; write-host -fore red $msg ; add-content -path $logfile -Value $msg}
  }

if ($ss.count -eq 0) {
$msg = "TERMINATING SCRIPT - Cannot connect to any IP address entered on port $LM_Port." ; write-host -fore red $msg ; add-content -path $logfile -Value $msg
read-host -Prompt "Press Enter to terminate script"
exit
}

$catch = start-sleep -milliseconds $wait

##################################
# Prompting for secure credentials 
##################################
# Use preprovisioned credentials (if available) to login to LoadMaster
$Creds = $Null
$password = ConvertTo-SecureString $LM_AdminPass -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential ($LM_Admin, $password)
$Login = Initialize-LmConnectionParameters -Address $ss[0] -LBPort $LM_Port -Credential $Creds
if ($Login.ReturnCode -eq 200) {
  $eapi = Enable-SecAPIAccess -LoadBalancer $ss[0] -Credential $Creds
  $msg = "200  - Login successful to $IP" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
}

# Prompt for credentials (if preprovisioned credentials are missing or are incorrect) to login to LoadMaster
if ($Login.ReturnCode -ne 200) {
do {
write-host -fore Green  "ENTER LOADMASTER ADMIN ACCOUNT AND PASSWORD VALID FOR ALL LOADMASTERS"
$Creds = Get-Credential -message "ENTER LOADMASTER ADMIN ACCOUNT AND PASSWORD"
$Login = Initialize-LmConnectionParameters -Address $ss[0] -LBPort $LM_Port -Credential $Creds
$eapi = Enable-SecAPIAccess -LoadBalancer $ss[0] -Credential $Creds
start-sleep -milliseconds 1000
}
while ($eapi.ReturnCode -ne "200")
}

# If $doPFX is set to True, prompt for password to install pfx based TLS certificates
if ($doPFX) {
  write-host -fore green "ENTER PASSWORD TO INSTALL PFX Certificates"
  $PFXPass = Read-Host "ENTER PASSWORD to install PFX Certificates" -AsSecureString
  $PFXPass = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PFXPass)
  $PFXPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($PFXPass)
  if ($PFXPass -eq "") {$doPFX = $False;  $msg = "200  - Skipping - Bypass - Install of PFX files"; write-host -fore cyan msg ; add-content -path $logfile -Value $msg }
}

# Collect password for admin user (userid/password)
if ($DoLMUser -and ($LM_UserPass -eq "")) {
  write-host -fore green "ENTER PASSWORD FOR ADMIN ACCOUNT $LM_User"
  $LM_UserPass = Read-Host "ENTER PASSWORD for $LM_User" -AsSecureString
  $LM_UserPass = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($LM_UserPass)
  $LM_UserPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($LM_UserPass)
  if ($LM_UserPass -eq "") {$DoLMUser = $False ; $msg = "200  - Skipping - Creation of admin user" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg}
}

# Collect password for ldap service account
if ($DoLDAP -and ($LDAP_UserPass -eq "")) {
  write-host -fore green "ENTER PASSWORD TO AUTHENTICATE $LDAP_USER TO LDAP SERVICE"
  $LDAP_UserPass = Read-Host "ENTER PASSWORD for $LDAP_User (LDAP SERVICE ACCOUNT)"  -AsSecureString
  $LDAP_UserPass = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($LDAP_UserPass)
  $LDAP_UserPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($LDAP_UserPass)
  if ($LDAP_UserPass -eq "") {$DoLDAP = $False; $msg = "200  - Skipping - Creation of LDAP service" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg}
}


#######################################################
# Check for minimum LoadMaster Operating System version
#######################################################
$LM_Required = "7.2.48.0"                                 # This is the required minimum release of LoadMaster Operating System for this script to function
$LM_R1 = ($LM_Required.Split("."))[0]
$LM_R2 = ($LM_Required.Split("."))[1]
$LM_R3 = ($LM_Required.Split("."))[2]
$LM_R4 = ($LM_Required.Split("."))[3]
foreach ($IP in $ss) {
$a = Get-LMAllParameters -LoadBalancer $IP

$LM_Version = $Null
$LM_Version = $a.data.AllParameters.version
$LM_V1 = ($LM_Version.Split("."))[0]
$LM_V2 = ($LM_Version.Split("."))[1]
$LM_V3 = ($LM_Version.Split("."))[2]
$LM_V4 = ($LM_Version.Split("."))[3]

if ($LM_V3 -ge $LM_R3) { 
$msg = "200  - LoadMaster LMOS validation PASSED for $IP" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
}
else {
$msg = "400  - LoadMaster LMOS validation FAILED for $IP" ; write-host -fore red $msg ; add-content -path $logfile -Value $msg
write-host -nonewline -fore Red "`nTERMINATING SCRIPT - Please patch LoadMaster to a minimum of version $LM_Required and rerun script: " ; read-host ; exit
}
}


###############################################################
# Ensure successful login to each LoadMaster in IP address list
###############################################################
foreach ($IP in $ss) {
$eapi = Enable-SecAPIAccess -LoadBalancer $ip
if ($eapi.ReturnCode -eq "200") {
$msg = "200  - LOGIN Test Passed to $IP" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg 
}
Else {
$msg = "400  - LOGIN Test Failed to $IP" ; add-content -path $logfile -Value $msg 
$msg = "Login test FAILED. Press any key to terminate script: " ; write-host -nonewline -fore red $msg ; read-host ; exit 
}
}


for ($i=0; $i -lt $ss.Count; $i++) {
  
  [string]$ip = $ss[$i]
  [string]$LM_Name = $nn[$i]

  $Login = Initialize-LmConnectionParameters -Address $ip -LBPort $LM_Port -Credential $Creds

if ($LM_AdminGW -eq "") {[string]$LM_AdminGW = (Get-LmParameter -LoadBalancer $ip -Param dfltgw).data.dfltgw }


  #####################################
  # Collect Common LoadMaster Variables
  #####################################
  [string]$iface0 = $null
  [string]$iface1 = $null
  [string]$eth0_IP = $Null
  [string]$eth0_CIDR = $Null
  [string]$eth1_IP = $Null
  [string]$eth1_CIDR = $Null
  
  $eapi = Enable-SecAPIAccess -LoadBalancer $ip
  $a = Get-LMAllParameters -LoadBalancer $ip 
  $doHA = ($a.data.AllParameters.hamode -ne 0)
  $unTether = ((get-licenseinfo -LoadBalancer $ip).data.LicenseInfo.mandatorytether -ne "yes")
  
  [string]$lmos_version = $a.data.AllParameters.version
  [int]$lm_minor = $lmos_version.split('.')[2]

  [string]$iface0 = (Get-NetworkInterface -LoadBalancer $ip -InterfaceID 0).data.interface.ipaddress
  [string]$iface1 = (Get-NetworkInterface -LoadBalancer $ip -InterfaceID 1).data.interface.ipaddress
  if ($iface0.length -ne 0) {[string]$eth0_IP = $iface0.split("/")[0]}                            # Extract eth0 IP address
  if ($iface0.length -ne 0) {[string]$eth0_CIDR = $iface0.split("/")[1]}                          # Extracy eth0 CIDR
  if ($iface1.length -ne 0) {[string]$eth1_IP = $iface1.split("/")[0]}                            # Extract eth1 IP address
  if ($iface1.length -ne 0) {[string]$eth1_CIDR = $iface1.split("/")[1]}                          # Extract eth1 CIDR
  if ($doHA) {[string]$LMSharedIP = (Get-NetworkInterface -LoadBalancer $ip).data.interface.sharedIPAddress[0].split('/')[0]}  # provides response as an IP address (e.g. 10.0.0.27)
    

  ##########################################
  # Set USG WARNING BANNER FOR Web Interface
  ##########################################
  if ($a.data.AllParameters.WUIPreAuth.Length -lt $WUIMsg.Length) {
  $postParams = @{param="WUIPreauth";value="$WUIMsg"}
  $uri = "https://" + $IP + ":" + $LM_Port + "/access/set"
  $catch = (Invoke-WebRequest -Method Post -Body $postParams -cred $creds -uri $uri).baseResponse.StatusCode
  if ($catch -eq "OK") {$catch = 200}
  $msg = "$catch  - Setting USG Default warning banner for web access" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
  start-sleep -Milliseconds $wait
  }
  else {$msg = "200  - Skipping - USG Default warning banner for web access already configured" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg}
  

  ##############################################
  # Set USG WARNING BANNER FOR Console Interface
  ##############################################
  if ($a.data.AllParameters.SSHPreauth.Length -lt $ConsoleMsg.Length) {
  $postParams = @{param="SSHPreauth";value="$ConsoleMsg"}
  $uri = "https://" + $IP + ":" + $LM_Port + "/access/set"
  $catch = (Invoke-WebRequest -Method Post -Body $postParams -cred $creds -uri $uri).baseResponse.StatusCode
  if ($catch -eq "OK") {$catch = 200}
  $msg = "$catch  - Setting USG Default warning banner for console access" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
  start-sleep -Milliseconds $wait
  }
  else {$msg = "200  - Skipping - USG Default warning banner for console already configured" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg}
  
  ######################################################
  # INSTALL INTERMEDIATE CERTIFICATES ON EACH LOADMASTER
  ######################################################
  if ($DoCER) {
    foreach ($CertFile in $CertList) {
    
      [int]$start=$CertFile.LastIndexOf('\') + 1
      [int]$length=$CertFile.LastIndexOf('.') - $CertFile.LastIndexOf('\') - 1
      $CertName=$CertFile.Substring($start,$length)
      $CertName = $CertName.Replace('.','-')
      $isit = ((Get-TlsIntermediateCertificate -LoadBalancer $ip -CertName "$CertName").ReturnCode -ne 200)
      if ($isit) {
        $catch = (New-TlsIntermediateCertificate -LoadBalancer $ip -Name "$CertName" -Path $CertFile).ReturnCode
        $msg = "$catch  - Installing Intermediate Certificate $CertFile as $CertName" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg 
        start-sleep -milliseconds 1500
      }
      Else {$msg = "200  - Skipping - Intermediate Certificate already installed - $CertName" ; write-host -fore cyan $msg; add-content -path $logfile -Value $msg }
    }
  }
  Else {$msg = "000  - Bypass - Intermediate Certificate Install" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }

  ####################################
  # DO PFX CERTIFICATE RELATED ACTIONS
  ####################################
    
  if ($doPFX) {
    #####################################################################
    # Determine Certificate Names for Shared and Local Admin IP Addresses
    #####################################################################
    [array]$pfxIPList = $Null
    [array]$certIPList = $Null
    [string]$SharedAdminCert = ""
    [string]$SharedAdminCertName = ""
    [string]$LocalAdminCert = ""
    [string]$LocalAdminCertName = ""

    # Determine local admin cert name            
    foreach ($pfxfile in $pfxlist) {
        $CertIPList = $Null
        $CertIPList = (certutil -p $pfxpass -v -dump $pfxfile | find "IP Address").trimstart("IP Address=")
        
        if ($CertIPList -ccontains $eth0_IP) {
        $LocalAdminCert = $pfxfile 
        [int]$start=$LocalAdminCert.LastIndexOf('\') + 1
        [int]$length=$LocalAdminCert.LastIndexOf('.') - $LocalAdminCert.LastIndexOf('\') - 1
        $LocalAdminCertName=$LocalAdminCert.Substring($start,$length)
        $LocalAdminCertName = $LocalAdminCertName.Replace('.','-')
        }
    }
     
    if ($doHA) {
        foreach ($pfxfile in $pfxlist) {
        $CertIPList = (certutil -p $pfxpass -v -dump $pfxfile | find "IP Address").trimstart("IP Address=")
        if ($CertIPList -ccontains $LMSharedIP) {$SharedAdminCert = $PFXFile} 
        }
        [int]$start=$SharedAdminCert.LastIndexOf('\') + 1
        [int]$length=$SharedAdminCert.LastIndexOf('.') - $SharedAdminCert.LastIndexOf('\') - 1
        $SharedAdminCertName=$SharedAdminCert.Substring($start,$length)
        $SharedAdminCertName=$SharedAdminCertName.Replace('.','-')
    }
 
    #######################
    # LOAD MANAGEMENT CERTS
    ####################### 
    if ($doHA) {
       $doit = ((get-tlscertificate -LoadBalancer $ip -CertName $SharedAdminCertName).ReturnCode -ne 200)
       start-sleep -Milliseconds $wait
       if ($doit) {
         $catch = (New-TlsCertificate -LoadBalancer $ip -Name $SharedAdminCertName -Path $SharedAdminCert -Password $pfxpass).ReturnCode
         $msg = "$catch  - Installing TLS Certificate $SharedAdminCertName" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
         start-sleep -Milliseconds 1000
       }
       Else {$msg = "200  - Skipping - Shared Admin Certificate already installed - $SharedAdminCertName" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
    }

    $doit = ((get-tlscertificate -LoadBalancer $ip -CertName $LocalAdminCertName).ReturnCode -ne 200)
    start-sleep -Milliseconds $wait
    if ($doit) {
      $catch = (New-TlsCertificate -LoadBalancer $ip -Name $LocalAdminCertName -Path $LocalAdminCert -Password $pfxpass).ReturnCode
      start-sleep -Milliseconds 1000
      $msg = "$catch  - Installing TLS Certificate $LocalAdminCertName" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
    }
    Else {$msg = "200  - Skipping - Local Admin Certificate already install - $LocalAdminCertName" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
 
  ################################
  # ASSIGN MANAGEMENT CERTIFICATES
  ################################
  $admincert = ((Get-LmParameter -LoadBalancer $ip -Credential $Creds -Param admincert).data.admincert -ne $LocalAdminCertName)
  if ($doHA) {
    Set-STIGParameter "admincert" "$SharedAdminCertName"
    Set-STIGParameter "localcert" "$LocalAdminCertName"
  }
  if (-Not $doHA) {
    Set-STIGParameter "admincert" "$LocalAdminCertName" 
  }
  }
  Else {$msg = "000  - Bypass - TLS Certificate Install" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  
  ############################################
  # Add local user for certificate based login
  ############################################
    if ($doCertUser) {
    $doit = ((get-secuser -LoadBalancer $ip -user "$LM_CertUser").ReturnCode -ne 200)
    if ($doit) {
      $catch = (New-SecUser  -LoadBalancer $ip -User "$LM_CertUser" -NoPassword).ReturnCode
      $msg = "$catch  - Added Certificate Login user $LM_CertUser" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      $catch = (Set-SecuserPermission  -LoadBalancer $ip -user "$LM_CertUser" -Permissions "root").ReturnCode
      $msg = "$catch  - Assigning rights to $LM_CertUser" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
    }
    Else {$msg = "200  - Skipping - Certificate based admin user already existst - $LM_CertUser" ;  write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  }
  Else {$msg = "000  - Bypass - Creation of admin user (certificate)" ;  write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  
  ###############
  # Configure NTP
  ###############
  if ($DoNTP) {
    $doit = ((Get-LmParameter -LoadBalancer $ip -Param "ntphost").data.ntphost -eq "")
    if (-not $doit) {
      $msg = "200  - Skipping - NTP already configured." ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
    }
    If ($doit -and (-not $NTPV3)) {
      $Catch = (Set-LmParameter -LoadBalancer $ip -Param ntpkeysecret -value "").ReturnCode
      $msg = "$catch  - Preparing for NTP authentication" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
      write-host -fore cyan "Setting NTP values can take some time."
      $Catch = (Set-LmParameter -LoadBalancer $ip -Param ntphost -value "$NTP_Name").ReturnCode
      $msg = "$catch  - Setting NTP Server to $NTP_Name." ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
    }
    if ($doit -and $NTPv3) {
      $Catch = (Set-LmParameter -LoadBalancer $ip -Param ntpkeytype -value "$NTPV3_KeyType").ReturnCode
      $msg = "$catch  - Setting NTP Key Type to $NTPV3_KeyType" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
      $Catch = (Set-LmParameter -LoadBalancer $ip -Param ntpkeyid -value "$NTPV3_KeyNum").ReturnCode
      $msg = "$catch  - Setting NTP Key Number to $NTPV3_KeyNum" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
      $Catch = (Set-LmParameter -LoadBalancer $ip -Param ntpkeysecret -value "$NTPV3_Secret").ReturnCode
      $msg = "$catch  - Setting NTP Key Number Secret to $NTPV3_Secret" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
      write-host -fore cyan "Setting NTP values can take some time."
      $Catch = (Set-LmParameter -LoadBalancer $ip -Param ntphost -value "$NTP_Name").ReturnCode
      $msg = "$catch  - Setting NTP Server to $NTP_Name." ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
    }
  }
  Else {$msg = "000  - Bypass - NTP configuration" ;  write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }


  ###########################
  # Create LDAP Configuration 
  ###########################
  if ($DoLDAP) {
    $doit = ((Get-LdapEndpoint  -LoadBalancer $ip -name "$LDAP_Name").data.LDAPEndPoint.name -ne "$LDAP_Name")
    if ($doIt) {
      $catch = (New-LdapEndpoint  -LoadBalancer $ip -Name $LDAP_Name -AdminPass $LDAP_Pass -AdminUser $LDAP_User -LdapProtocol $LDAP_Protocol -Server $LDAP_Servers).ReturnCode
      $msg = "$catch  - Creating new LDAP endpoint named $LDAP_Name" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
    }
    else {$msg = "200  - Skipping - LDAP Endpoint already exists - $LDAP_Name" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  }
  else {$msg = "000  - Bypass - LDAP Endpoint configuration" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }

  #################
  # Add Local Group
  #################
  if ($DoLDAPGroup) {write-host -fore cyan "`nAttempting to create LoadMaster admin group"
    $doit = ((Get-SecRemoteUserGroup  -LoadBalancer $ip -group "$LDAP_Group").returnCode -ne 200)
    if ($doit) {
      $catch = (New-SecRemoteUserGroup  -LoadBalancer $ip -Group "$LDAP_Group").ReturnCode
      $msg = "$catch  - Created Admin Group $LDAP_Group" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
      $catch = (Set-SecRemoteUserGroup  -LoadBalancer $ip -group "$LDAP_Group" -Permissions "root,users").ReturnCode
      $msg = "$catch - Assigning rights to $LDAP_Group - $IP" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
    }
    Else {$msg = "200  - Skipping - Admin Group already exists - $LDAP_Group" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg}
  }
  else {$msg = "000  - Bypass - Local Admin Group configuration" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }

  #########################################
  # Add local user for password based login
  #########################################
  if ($DoLMUser) {
    $doit = ((get-secuser  -LoadBalancer $ip -user "$LM_User").ReturnCode -ne 200)
    if ($doit) {
      $catch = (New-SecUser  -LoadBalancer $ip -User "$LM_User" -Password "$LM_UserPass").ReturnCode
      $msg = "$catch  - Create new admin user" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      $catch = (Set-SecuserPermission  -LoadBalancer $ip -user "$LM_User" -Permissions "root,users").ReturnCode
      $msg = "$catch  - Root permissions assigned to $LM_User" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait
    }
    Else {$msg = "200  - Skipping - Admin user (password) already exists - $LM_User" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  }
  Else {$msg = "000  - Bypass - Admin user (password) configuration" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }

  
  ##########################
  # Create FIPS++ Cipher Set
  ##########################
  $doit = ((get-TLSCipherSet -LoadBalancer $ip -Name FIPS++).returncode -ne 200)
  if ($doit) {
    [string]$newcipherlist = $null
    [array]$oldcipherlist = (Get-TlsCipherSet -LoadBalancer $ip -name FIPS).data.TlsCipherSet
    foreach ($cipher in $oldcipherlist) {
      if (($newcipherlist -eq $null) -and ($cipher -notlike "DES-*") -and ($cipher -notlike "*-SHA") -and ($cipher -notlike "DHE-*")) {$newcipherlist = "$cipher"}
      if (($newcipherlist -ne $null) -and ($cipher -notlike "DES-*") -and ($cipher -notlike "*-SHA") -and ($cipher -notlike "DHE-*")) {$newcipherlist = "$newcipherlist" + ":" + "$cipher"}
    }
    $catch = (Set-TlsCipherSet -LoadBalancer $ip -name "FIPS++" -value $newcipherlist).ReturnCode
    $msg = "$Catch  - Created FIPS++ Custom Cipher Set to delete DHE, 3DES and SHA1" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
    start-sleep -Milliseconds $wait
  }
  Else {$msg = "200  - Skipping - FIPS++ cipher set already exists" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  
  ###################################################
  # Enable Management on Eth1 if iface1 is configured
  ###################################################
  if ($iface1.length -gt 4) {
    start-sleep -Milliseconds $wait
    $doit = ((Get-NetworkInterface -LoadBalancer $ip -InterfaceID 1).data.interface.adminwuienable -ne "yes")
    if ($doit) {
      $uri = "https://$IP" + ":" + $LM_Port + "/access/modiface?interface=1&adminwuienable=1"
      $Catch = (curl $uri -cred $creds).BaseResponse.StatusCode
      if ($catch -eq "OK") {$catch = 200}
      $msg = "$catch  - Management has been enabled on eth1" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
      start-sleep -Milliseconds $wait ;   Set-STIGParameter "multigw" "yes"    # Allow movement of default gateway to a different network interface
      start-sleep -Milliseconds $wait
     }
    Else {$msg = "200  - Skipping - Management on eth1 is already enabled" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  }
  else {$msg = "000  - Bypass - Configuration of eth1. No IP address assigned" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }

  #########################
  # Disable GEO Feature Set
  #########################
  $doit = ((Get-GeoStatistics -LoadBalancer $ip).returncode -eq 200)
  if ($doit) {
   $Catch = (Disable-LmGeoPack -LoadBalancer $ip).ReturnCode
   $msg = "$catch  - Disable GEO Feature Set" ; write-host -fore cyan $msg ; add-content -path $logfile -value $msg
   start-sleep -Milliseconds $wait
  }
  Else {$msg = "200  - Skipping - GEO feature is already disabled" ; write-host -fore cyan $msg ; add-content -path $logfile -value $msg }

 
  ####################################################
  # SET VARIOUS OPTIONS TO MEET DODIN APL REQUIREMENTS
  ####################################################
  

  start-sleep -Milliseconds $wait ; Set-STIGParameter "sessioncontrol" "yes"                        # Enable WUI login session management
  start-sleep -Milliseconds $wait ; Set-STIGParameter "sessionbasicauth" "no"                       # Disables WUI basic authentication
  start-sleep -Milliseconds $wait ; Set-STIGParameter "hostname" "$LM_Name"                         # Set LoadMaster hostname
  start-sleep -Milliseconds $wait ; Set-STIGParameter "snat" "yes"                                  # Enable Server NAT
  start-sleep -Milliseconds $wait ; Set-STIGParameter "sshaccess" "no"                              # Disable SSH access to LoadMaster
  start-sleep -Milliseconds $wait ; Set-STIGParameter "nonlocalrs" "yes"                            # Enable VS to use non-local real servers
  start-sleep -Milliseconds $wait ; Set-STIGParameter "subnetorigin" "yes"                          # Enable Subnet Originating requests (SOR)
  start-sleep -Milliseconds $wait ; Set-STIGParameter "sslrenegotiate" "no"                         # Disable SSL renegotiation
  start-sleep -Milliseconds $wait ; Set-STIGParameter "admingw" "$LM_AdminGW"                       # Explicitly assign management gateway
  start-sleep -Milliseconds $wait ; Set-STIGParameter "onlydefaultroutes" "yes"                     # Enable VS to properly use explicitly defined gateways
  start-sleep -Milliseconds $wait ; Set-STIGParameter "KcdCipherSha1" "yes"                         # Force kerberos to use SHA algorithms
  start-sleep -Milliseconds $wait ; Set-STIGParameter "CEFMsgFormat" "yes"                          # Enable Common Event Format based logging
  start-sleep -Milliseconds $wait ; Set-STIGParameter "WUITLSProtocols" "3"                         # Restict Wed User Interface to TLS1.1, TLS1.2 and TLS1.3
  start-sleep -Milliseconds $wait ; Set-STIGParameter "WUITLS13Ciphersets" "TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256"   # Set TLS1.3 WUI Cipher Set  (space separated list)
  start-sleep -Milliseconds $wait ; Set-STIGParameter "outboundcipherset" "FIPS"                 # Setting Outbound cipher to FIPS++ or FIPS for newer code
  start-sleep -Milliseconds $wait ; Set-STIGParameter "WUICipherset" "FIPS"                      # Setting Inbound (WUI) cipher to FIPS++ or FIPS for newer code  
  start-sleep -Milliseconds $wait ; if ($iface1.Length -gt 4) {Set-STIGParameter "MultiHomedWui" "yes"}                      # Enable Multi-Interface WUI Management if iface1 is configured
  start-sleep -Milliseconds $wait ; if ($Untether) {Set-STIGParameter "Tethering" "no"}                                     # If license type is permanent, untether (turn off call home)

  #############################################
  # Set login method to Certificate or Password 
  #############################################
  if ($doCertuser) {
    $doit = ((Get-SecRemoteAccessLoginMethod -LoadBalancer $ip).data.loginmethod -ne "PasswordOrClientCertificate")
    if ($doit -and ($lm_minor -eq 56)) {
      write-host -fore cyan -fore DarkYellow "There is a bug in using the API to apply login methods"
      write-host -fore cyan -fore DarkYellow "Go to WUI and enable Password or Client Certificate login method."
      write-host -fore cyan -fore DarkYellow "After manually setting this parameter, test cert login "
      read-host -Prompt "Press enter one actions are complete."
    }
    if ($doit -and ($lm_minor -gt 56)) {
      $Catch = (Set-SecRemoteAccessLoginMethod -LoadBalancer $ip -LoginMethod PasswordorClientCertificate).ReturnCode
      $msg = "$catch  - Setting LoadMaster WUI Login Method to Password or Client Certificate" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg
    }
    if (-not $doit) {$msg = "200  - Skipping - LoadMaster WUI Login Method already set to - PasswordorClientCertificate" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
  }
  Else {$msg = "000  - Bypass - Setting login method to password or certificate" ;  write-host -fore cyan $msg ; add-content -path $logfile -Value $msg }
 }


###########################
# Clear sensitive variables
###########################
#$LM_UserPass = $Null
#$pfxpass = $Null
#$LDAP_Pass = $Null
#remove-item -path ".\certlist.txt" -Force -recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
#remove-item -path ".\pfxlist.txt" -Force -recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue


#################
# END OF SCRIPT #
#################
#$msg = "`nSCRIPT COMPLETED" ; write-host -fore cyan $msg ; add-content -path $logfile -Value $msg



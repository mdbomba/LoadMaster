# THIS SCRIPT APPLIES SECURITY SETTINGS TO LOADMASTER APPLIANCES LMOS 7.2.54 AND NEWER

# CRITICAL NOTE: PLEASE EDIT CONFIGURATION PARAMETERS BEFORE RUNNING SCRIPT

# DESIGNED TO RUN ON WINDOWS 11 POWERSHELL 5.1 AND LINUX POWERSHELL 7.2

# CHANGE LOG
# Compensated for dirty response to get-param admincert
# Compensated for dirty response to get-param localcert
# Created custom cipher set FIPS2 to match our revised FIPS algorithm set
# Applied FIPS2 cipher set to management traffic
# Added necessary logic to support appliances set to Software FIPS Mode

###################################
# Cleanup and prepare to run script
###################################
clear-history
clear-host
Remove-Variable * -ErrorAction SilentlyContinue
[string]$ScriptVersion = "v3.20230906"

#######################################################################
############### START OF CONFIGURATION PARAMETERS SECTION #############

[bool]$doFIPS2 = $True            # ENTER $True to Create restricted FIPS cipher set removing weak ciphers ($False to skip)
[bool]$doGEO = $True              # ENTER $True to Process GEO settings according to $EnableGEO value ($False to skip GEO setting)
[bool]$doPassUser = $True         # ENTER $True to Create new admin account based on username and password ($False to skip)
[bool]$doCertUser = $True         # ENTER $True to Create new admin account based on certificate principal name ($False to skip)
[bool]$doPEM = $True              # ENTER $True to Install management certificate (.pem file) ($False to skip)
[bool]$doAdminCert = $True        # ENTER $True to Assign management certificate to WUI interface ($False to skip)
[bool]$doCer = $True              # ENTER $True to Install intermediate certificates (base64 .cer file) ($False to skip)
[bool]$doHostName = $True         # ENTER $True to assign a hostname based on $hostbase + $IP ($False to skip)
[bool]$doNTP = $True              # ENTER $True to configure LoadMaster for NTP ($False to skip)
[bool]$doNTPv3 = $False           # ENTER $True to if NTP service should use NTPv3 ($False to skip)
[bool]$doLdap = $True             # ENTER $True to configure an LDAP service connection ($False to skip)
[bool]$doLdapGroup = $True        # ENTER $True to configure an LDAP management group ($False to skip)
[bool]$doWarningBanners = $True   # ENTER $True to configure WUI and Console warning banners ($False to skip)
[bool]$EnableGEO = $False         # Enter $True to enable GEO, $False to disable GEO Load Balancing service (disable port 53 listener)
[string]$hostbase = 'VLM'         # ENTER a name to create hostname prefix ('' will skip process)
[string]$NewCertUser = 'Mike@KEMPTECH.BIZ' # ENTER a name to create a certificate login admin user, CASE SENSITIVE (typically certificate Principal Name)
[string]$NewPassUser = 'adminmike'         # ENTER a name to create a name/password login admin user ('' will skip process)
[string]$NewPassUserPass = '<CHANGE_ME_PASSWORD>'  # ENTER a password for new name/password admin user ('' will skip process)
[string]$NewUserGroup = 'Kemp'    # ENTER a name to LDAP admin group ('' will skip process)
[string]$NewUserRights = 'root'   # ENTER rights for new user or group objects (root - all rights) ('' will skip process)
[string]$sor = 'yes'              # ENTER 'yes' to enable Subnet Originating Request appliance wide ('' will skip process)
[string]$ntpv3_keynum = ''        # ENTER NTPv3 Key Number ('' will skip process)
[string]$ntpv3_keytype = ''       # ENTER NTPv3 Key Type ('' will skip process)
[string]$ntpv3_secret = ''        # ENTER NTPv3 Key Secret ('' will skip process)
[string]$ntp_host = 'time.nist.gov'        # ENTER NTP Server name or IP address ('' will skip process)
[string]$ldap_Name = 'KEMPTECH.BIZ'        # ENTER LDAP Service name or IP address ('' will skip process)
[string]$ldap_Server = '10.0.0.10'         # ENTER LDAP Server name or IP address ('' will skip process)
[string]$ldap_User = 'ldapuser'            # ENTER LDAP Service Account Name ('' will skip process)
[string]$ldap_UserPass = '<CHANGE_ME_PASSWORD>'    # ENTER LDAP Service Account Password ('' will skip process)
[int]$ldap_Type = 0               # ENTER LDAP Service Protocol (0 = LDAP, 1 = STARTTLS, 2 = LDAPS, '' will skip process)
[string]$WUI_IdleTime = '600'     # ENTER WUI Session Idle Logout Timer in seconds ('' will skip process)
[string]$WUI_FailedLogins = '5'   # ENTER WUI Session Max Failed Logins ('' will skip process)
[string]$WUI_MaxLogins = '3'      # ENTER WUI Session Max Concurrent Logins ('0' will not set a limit)
[string]$certpath = '.\certs\wc.pem'       # ENTER filename and path for TLS Management Certificate (PEM format only) ('' will skip process)
[string]$certpass = 'password'    # ENTER Password to install encrypted private key in TLS Management Certificate"
[string]$certname = 'wc'          # ENTER friendly name for TLS Management Certificate"
[string]$ica1 = '.\certs\ECC.cer'  # ENTER filename and path for Intermediate Certificate File (PEM format only) 
[string]$ica2 = '.\certs\RSA.cer'            # ENTER filename and path for Intermediate Certificate File (PEM format only) (Enter ‘none’ instead of ‘’ as needed)
[string]$ica3 = 'none'            # ENTER filename and path for Intermediate Certificate File (PEM format only) (Enter ‘none’ instead of ‘’ as needed)
[string]$ica4 = 'none'            # ENTER filename and path for Intermediate Certificate File (PEM format only) (Enter ‘none’ instead of ‘’ as needed)
[string]$workingDir = "~\loadmaster"       # If necessary, set this to a different location you have read/write rights
#
[string]$ConsoleMsg = "USG Warning Banner - YOU ARE ACCESSING A US GOVERNMENT (USG) INFORMATION SYSTEM PROVIDED FOR AUTHORIZED USE ONLY. Communications using, or data stored on this Information System are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any authorized purpose. USG logs all access to this system. Upon proper legal request, these logs and any other related data will be released for personnel misconduct and law enforcement purposes. Unauthorized use of this system will be prosecuted. By continuing to login, you agree to the above terms and conditions."
#
[string]$WUIMsg = "<!DOCTYPE html><html><head><title>USG Warning Banner</title></head><style>p {color: black;}.title1 {font-size: 13px;text-align: center;}.paragraph1 {font-size: 12px; text-align: left;}</style><h1>USG WARNING AND CONSENT BANNER</h1><hr><p class=title1>YOU ARE ACCESSING A UNITED STATES GOVERNMENT (USG) INFORMATION SYSTEM<br>PROVIDED FOR AUTHORIZED USE ONLY</p><br><p class=paragraph1>By using this Information System (which includes any device attached to this Information System), you consent to the following conditions:<br><br>- USG routinely intercepts and monitors communications on this Information System for purposes including, but not limited to, penetration testing, network operations and defense, and upon proper legal request for personnel misconduct and law enforcement purposes.<br><br>- At any time, the USG may inspect and seize data stored on this Information System. Communications using, or data stored on this Information System are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any authorized purpose. This Information System includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.<br><br> - Notwithstanding the above, using this Information System does not constitute consent to legal or criminal investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. <br><br> - USG requires all USG personnel to complete Information System Security training annually.<br><br>- By continuing to login, you agree to the above terms and conditions.</p></body></html>"
#
[string]$FIPS2 = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:AES128-GCM-SHA256:AES128-SHA256"
#
##### OPTIONAL PARAMETERS - IF ENTERED HERE WILL NOT BE PROMPTED FOR LATER #####
[array]$iplist = '10.0.0.90'               # If set to '', you will be prompted for a list of LoadMaster IP addresses
[string]$port = '443'                      # If set to '', you will be prompted for the LoadMaster API port number
[string]$lmadmin = 'bal'                   # if set to '', you will be prompted for a LoadMaster amin account
[string]$lmadminpass = 'Kemp1fourall'      # if set to '', you will be prompted for the LoadMaster admin account password 
  
############## END OF CONFIGURATION SECTION #################
#############################################################

[string]$time = (Get-Date -Format u)

################################
# Change directory to workingDir
################################
Set-Location -Path $workingDir

#################
# DEFINE LOG FILE 
#################  
$logfile = "$workingdir\LoadMaster_STIG.log"      
if (test-path -Path $logfile -PathType leaf) {
  Get-Date  >> $logfile
  $msg >> $logfile
  "LoadMaster STIG Script $scriptversion log file`n" >> $logfile 
} 
Else {
  Get-Date  > $logfile
  $msg >> $logfile
  "LoadMaster STIG Script $scriptversion log file`n" >> $logfile 
}

###########################################
# Populate $certlist for intermediate certs
###########################################
[array]$certlist = $Null
if (($ica1.length -gt 0) -and ($ica1 -ne "none") -and (test-path -path $ica1 -PathType Leaf)) {$certlist += $ica1}
if (($ica2.length -gt 0) -and ($ica2 -ne "none") -and (test-path -path $ica2 -PathType Leaf)) {$certlist += $ica2}
if (($ica3.length -gt 0) -and ($ica3 -ne "none") -and (test-path -path $ica3 -PathType Leaf)) {$certlist += $ica3}
if (($ica4.length -gt 0) -and ($ica4 -ne "none") -and (test-path -path $ica4 -PathType Leaf)) {$certlist += $ica4}
if ($certlist.length -eq 0) {$doCER = $False; $doCertUser = $False}

########################
# Provide info on script
########################
$ps = (get-host).version
$os = [System.Environment]::OSVersion.Platform
[bool]$ps7 = ($ps.major -ge 7)
[bool]$w32 = ($os -match "Win32NT")

$msg = "SCRIPT TO APPLY STIG SETTINGS TO LOADMASTER"; Write-Host -Fore cyan $msg; $msg >> $logfile
$msg = "$time  INFO - Workstation Operating System ($os)"; $msg; $msg >> $logfile
$msg = "$time  INFO - Workstation PowerShell Version ($ps)"; $msg; $msg >> $logfile

##############################################################################
# ENABLE WEB CONNECTIONS TO IGNORE CERTIFICATE ERRORS AND USE TLS1.2 OR NEWER
##############################################################################
if (Test-Path -Path "~\.curlrc" -pathtype Leaf) {Copy-Item -Path "~/.curlrc" "~/.oldcurlrc" -Force}
echo "--insecure" > ~/.curlrc
echo "--tls1.2" >> ~/.curlrc
$msg = "$time  INFO - Created .curlrc file with --insecure and --tls1.2 params"; $msg; $msg >> $logfile

if ($ps7) {$msg = "$time  INFO - Added options for Invoke-Webrequest for PowerSHell v7"; $msg; $msg >> $logfile}
Else {$msg = "$time  INFO - Added options for Invoke-Webrequest for PowerSHell v5"; $msg; $msg >> $logfile}

if ($w32 -and $ps7) {
  [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True } 
  [System.Net.ServicePointManager]::SecurityProtocol = "tls12, tls11"                                       
  $msg = "$time  INFO - Set Windows PowerShell 7 to ignore Cert Valication Errors"; $msg; $msg >> $logfile
}
if ($w32 -and -not $ps7) {
  if (([System.Net.ServicePointManager]::CertificatePolicy).ToString() -ne "TrustAllCertsPolicy") {
    add-type @"
      using System.Net;
      using System.Security.Cryptography.X509Certificates;
      public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
          ServicePoint srvPoint, X509Certificate certificate,
          WebRequest request, int certificateProblem) {
           return true;
        }
    }
"@
  [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
  }
  [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11" 
  $msg = "$time  INFO - Set Windows PowerShell 5 to ignore Cert Validation Errors"; $msg; $msg >> $logfile
}

############################
# STANDARD GLOBAL PARAMETERS 
############################          
$pattern1 = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
$pattern2 = '^(\d{1,4})$'
$wait = 250                                        ## Recommend you leave this value as is. 

######################################################################
# CHECK FOR REQUIRED PARAMETERS FOR LOGIN - PROMPT FOR VALUE AS NEEDED
######################################################################
# LOADMASTER ADMIN ACCOUNT
if ($lmadmin.length -eq 0) {
  do {
   $lmAdmin = Read-Host -Prompt "Enter LoadMaster Amin Account (e.g. bal)"
  } while ($lmAdmin.length -lt 1)
}
# LOADMASTER ADMIN ACCOUNT PASSWORD
if ($lmadminpass.Length -eq 0) {
  do {
   "Enter password for $lmadmin in secure popup box"
   $Pass = Read-Host "ENTER PASSWORD for $lmadmin" -AsSecureString 
   $Pass = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pass)
   $lmAdminPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pass)
  } while ($lmAdminPass.length -lt 8)
}
# LOADMASTER API INTERFACE PORT
if ($port.length -eq 0) {do {$port = read-host -Prompt "Enter LoadMaster WUI Port (e.g. 443 or 8443)"} while ($port.length -lt 1) }
# LOADMASTER API INTERFACE IP ADDRESS LIST
if (($iplist.count -eq 0) -or ($iplist[0].length -lt 5)) {
  do {
    $ip = read-host -Prompt "Enter all LoadMaster WUI IP Addresses (blank line to finish)"
    if ($ip -match $pattern1) {$iplist += $ip} 
    ElseIF ($ip -ne "") {"ERROR IN IP ADDRESS FORMAT"}
  } while ($ip -ne '')
  $iplist = $iplist.Where({ $_ -ne "" })
}


"################ START ##############" >> $logfile
$msg = "$time  INFO - Working directory ($workingdir)"; $msg; $msg >> $logfile

###############################################
# Function to Ping a Port with variable timeout
###############################################
function Test-Port ($ip, $port, $Timeout) {
  [bool]$ps7 = ((get-host).version.major -ge 7)
  if ($ip.length -eq 0) {$ip = $lmip}
  if ($port.length -eq 0) {$port = $lmport}
  if ($Timeout.length -le 0) {$Timeout = '1000'}
  if ($port.length -le 0) {$port = '443'}
  if ($ps7) {test-connection -computername $ip -TcpPort $port}
  else {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $tcpClient.ConnectAsync($ip, $port).Wait($Timeout)
  }
}

##################################
# Function to Enable API Interface
##################################
function Enable-LMapi ($ip, $port, $APIUser, $APIPass) {
  [bool]$ps7 = ((get-host).version.major -ge 7)
  if ($ip.length -eq 0) {$ip = $lmip}
  if ($port.length -eq 0) {$port = $lmport}
  if ($APIUser.Length -eq 0) {$APIUser = $lmadmin}
  if ($APIPass.Length -eq 0) {$APIPass = $lmadminpass}
  $ipport = $ip+":"+$port
  $url = "https://$ipport/accessv2"
  $cmd = 'set'
  $param = 'enableapi'
  $value = 'yes'
  $body = '{"apiuser":"'+$APIUser+'","apipass":"'+$APIPass+'","cmd":"'+$cmd+'","param":"'+$param+'","value":"'+$value+'"}'
  if ($ps7) {$rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method post -uri $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}}
  else {$rc = try {$r = (Invoke-WebRequest -Method post -uri $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}}
  if ($r.code -match '200') {$msg = "$time  INFO - LoadMaster API Interface is Enabled"; $msg; $msg >> $logfile }
}


###################################
# DEFINE FUNCTION TO COLLECT APIKEY
###################################
# APIKEY can only be generated AFTER LoadMaster is licensed
function get-apikey ($ip, $port, $Credential) {
  if ($ip.length -eq 0) {$ip = $lmip}
  if ($port.length -eq 0) {$port = $lmport}
  if ($Credential.lengh -eq 0) {$Credential = $creds}
$ipport = $ip+":"+$port
[bool]$ps7 = ((get-host).version.major -ge 7)
[string]$url = $Null; $url = "https://$ipport/access/addapikey"
if ($ps7) {$rc = try {$r = Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri $url -Credential $Credential} catch {'{"code":"422"}' | ConvertFrom-Json}}
Else {$rc = try {$r = Invoke-WebRequest -Method Get -Uri $url -Credential $Credential} catch {'{"code":"422"}' | ConvertFrom-Json}}
$res = $r.RawContent.tostring()
$start = $res.indexof('<key>') + 5
$end  = $res.indexof('</key>')
$apikey = $res.substring($start, ($end - $start))
$apikey
}
################

###################################################################
# CREATE SHORTCUT TO POST API COMMANDS (APIv2) SUPPORTING PS7 & PS5
###################################################################
FUNCTION post-command ($url, $body) {
  [System.Uri]$u = $url
  # Determine if running on PowerShell 7 or newer
  [bool]$ps7 = ((get-host).version.major -ge 7)
  if ($ps7) {$output = $Null; $output = Invoke-WebRequest -SkipCertificateCheck -Method post -uri $u -Body $body}
  else {$output = $Null; $output = Invoke-WebRequest -Method post -uri $u -Body $body}
  $output
  start-sleep -Milliseconds 250
}
###################################################################

##########################################################
# CREATE FUNCTION TO SET PARAMETERS USING DIRECT API CALLS
##########################################################
FUNCTION set-param ($ip, $port, $param, $value, $APIKey, $APIUser, $APIPass) {
  # Determine if running on PowerShell 7 or newer
  [bool]$ps7 = ((get-host).version.major -ge 7)
  if ($ip.length -eq 0) {$ip = $lmip}
  if ($port.length -eq 0) {$port = $lmport}
  if ($APIKey.length -eq 0) {$APIKey = $lmAPIKey}
  if ($APIUser.Length -eq 0) {$APIUser = $lmadmin}
  if ($APIPass.Length -eq 0) {$APIPass = $lmadminpass}
  if ($value.Length -gt 60) {$val = $value.Substring(0,60)} Else {$val = $value}
  $ipport = $ip+":"+$port
  $url = "https://$ipport/accessv2"
  $cmd = 'get'
  if ($apikey.length -gt 1) {$body = '{"apikey":"'+$apikey+'","cmd":"'+$cmd+'","param":"'+$param+'"}'}
  else {$body = '{"apiuser":"'+$APIUser+'","apipass":"'+$APIPass+'","cmd":"'+$cmd+'","param":"'+$param+'"}'}
  if ($ps7) {$asis = $Null; $asis = (Invoke-WebRequest -SkipCertificateCheck -Method post  -uri $url -Body $body | convertfrom-json).$param}
  else {$asis = $Null; $asis = (Invoke-WebRequest -Method post  -uri $url -Body $body | convertfrom-json).$param}
  if ($asis -eq $value) {$msg = "$time  SKIP - $param already set to $val"; $msg; $msg >> $logfile}
  else {
    $url = "https://$ipport/accessv2"
    $cmd = 'set'
    if ($apikey.length -gt 1) {$body = '{"apikey":"'+$apikey+'","cmd":"'+$cmd+'","param":"'+$param+'","value":"'+$value+'"}'}
    else {$body = '{"apiuser":"'+$apiuser+'","apipass":"'+$apipass+'","cmd":"'+$cmd+'","param":"'+$param+'","value":"'+$value+'"}'}
    if ($ps7) {$rc = $Null; $rc = (Invoke-WebRequest -SkipCertificateCheck -Method post  -uri $url -Body $body | convertfrom-json).code}
    else {$rc = $Null; $rc = (Invoke-WebRequest -Method post  -uri $url -Body $body | convertfrom-json).code}
    if ($rc -match '200') {$msg = "$time   SET - $param set to $val"; $msg; $msg >> $logfile }
    else {$msg = "$time   ERR - Cannot set $param to $val"; $msg; $msg >> $logfile}
  }
  start-sleep -Milliseconds 250
}
##########################################################

##########################################################
# CREATE FUNCTION TO GET PARAMETERS USING DIRECT API CALLS
##########################################################
function Get-Param ($ip, $port, $param, $APIKEY) {
  # Determine if running on PowerShell 7 or newer
  [bool]$ps7 = ((get-host).version.major -ge 7)
  if ($ip.length -eq 0) {$ip = $lmip}
  if ($port.length -eq 0) {$port = $lmport}
  if ($APIKey.length -eq 0) {$APIKey = $lmAPIKey}
  $ipport = $ip+":"+$port
  $url = "https://$ipport/accessv2"
  $cmd = 'get'
  $body = '{"apikey":"'+$apikey+'","cmd":"'+$cmd+'","param":"'+$param+'"}'
  if ($ps7) {$asis = $Null; $asis = (Invoke-WebRequest -SkipCertificateCheck -Method post  -uri $url -Body $body | convertfrom-json).$param}
  else {$asis = $Null; $asis = (Invoke-WebRequest -Method post  -uri $url -Body $body | convertfrom-json).$param}
  $asis
}



##########################################################
# Run sanity checks and reset do##### parameters as needed
##########################################################
if ($certpass.length -eq 0) {$doPEM = $False}
if ($certname.length -eq 0) {$doPEM = $False}
if ($certpath.split(".")[-1] -notmatch "pem") {$doPEM = $False}
if ($NewCertUser.length -eq 0)  {$doCertUser = $False}
if ($NewPassUser.length -eq 0)  {$doPassUser = $False}
if ($NewPassUserPass.length -eq 0)  {$doPassUser = $False}
if ($NewUserGroup.length -eq 0) {$doLdapGroup = $False}
if ($NewUserRights.length -eq 0) {$NewUserRights = 'readonly'}  # need to verify this
if ($ldap_Name.length -eq 0) {$doLdap = $False}
if ($ldap_Server.length -eq 0) {$doLdap = $False}
if ($ldap_User.length -eq 0) {$doLdap = $False}
if ($LDAP_UserPass.length -eq 0) {$doLdap = $False}
if ($ldap_Type.length -eq 0) {$ldap_Type = '0'}
if ($ntpv3_keynum.length -eq 0) {$doNTPv3 = $False}
if ($ntpv3_keytype.length -eq 0) {$doNTPv3 = $False}
if ($ntpv3_secret.length -eq 0) {$doNTPv3 = $False}
if ($ntp_host.length -eq 0) {$doNTP = $doNTPv3 = $False}
if ($hostbase.length -eq 0) {$dohostname = $False}
if ($FIPS2.length -eq 0) {$doFIPS2 = $False}


################################
# Process all entries in $iplist
################################
$ip = $Null
foreach ($ip in $iplist) {
  [string]$lmip = $ip
  [string]$lmport = $port
  [string]$ipport = $ip + ":" + $Port
  [string]$hostname = $hostbase + '-' + $ip.split('.')[-1]
  $msg = "STARTING CONFIGURATION $hostname at $ipport"; Write-Host -fore cyan $msg; $msg >> $logfile
  
  ############################################
  # Test connectivity and skip entry as needed
  ############################################
  if ((test-port)) {
    $msg =  "$time  INFO - PASSED CONNECTION TEST TO $ipport"; $msg; $msg >> $logfile
  }
  Else {$msg =  "$time  SKIP - SKIPPING PROCESSING FOR $IP - CANNOT CONNECT"; $msg; $msg >> $logfile ; continue}

  #################################
  # ENSURE API INTERFACE IS ENABLED
  #################################
  enable-LMapi -ip $ip -port $port -APIUser $lmadmin -APIPass $lmadminpass
  
  #########################
  # Build credential object 
  #########################
  $creds = $Null; $creds = New-Object pscredential("$lmadmin", (ConvertTo-SecureString -String "$lmadminpass" -AsPlainText -Force))  
  $apikey = $Null; $lmAPIKey = $apikey = get-apikey -ip $ip -port $port -Credential $creds
  [string]$url = $Null; [string]$url = "https://$ipport/accessv2"
  
  ##############################
  # Collect data from LoadMaster
  ##############################

  # Collect a list of all available api commands
  [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"listapi"}'
  [array]$allapi = $Null; [array]$allapi = (post-command -url $url -Body $body | convertfrom-json).commands

  # Collect a list of all available license info
  [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"licenseinfo"}'
  [array]$licenseinfo = $Null; [array]$licenseinfo = (post-command -url $url -Body $body | convertfrom-json)
  
  # Collect a list of all available parameters and values
  [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"getall"}'
  [array]$allparams = $Null; [array]$allparams = (post-command -url $url -Body $body | convertfrom-json)

  # Test for FIPS Mode active
  [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"set","param":"WUICipherset","value":"FIPS"}'
  $FIPSModeTest = $Null; $FIPSModeTest = try {(post-command -url $url -Body $body).statuscode} catch {$_}; $FIPSModeTest = $FIPSModeTest.tostring()
  $FIPSMode=$Null; $FIPSMode = $FIPSModeTest.contains("protocol violation")
  if ($FIPSMode) {$doFIPS2 = $False; $msg = "$time  INFO - LoadMaster is running in Software FIPS Mode. Ciphersets will be set to Default."; write-host -fore Yellow $msg; $msg >> $logfile}

  ###############################################
  # VALIDATE INFO NEEDED FOR OPTIONS IS AVAILABLE
  ###############################################
    
  #######################################################
  # Check for minimum LoadMaster Operating System version
  #######################################################
  [string]$LM_R = "54"
  [string]$LM_V = ($allparams.version).Split(".")[2]

  if ($LM_V -ge $LM_R) {$msg = "$time  INFO - LoadMaster LMOS equal or greater than 7.2.$LM_R. Validation PASSED"; $msg; $msg >> $logfile }
  else {$msg = "$time  SKIP - LoadMaster LMOS less than 7.2.$LM_R. Validation FAILED."; $msg; $msg >> $logfile; return } 
  start-sleep -Milliseconds 250
 
  ###################
  # ASSIGN Cipher Set
  ###################

  # Determine cipher set to assign
  if (($LM_V -lt 59) -and ($doFIPS2)) {[string]$cipher = 'FIPS2'}
  if (($LM_V -ge 59) -and ($doFIPS2)) {[string]$cipher = 'FIPS'; $doFIPS2 = $False}
  if (-not $doFIPS2) {[string]$cipher = 'Default'}

  # Test to see if FIPS2 cipher set already exists
  if ($doFIPS2) {
    [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"getcipherset","name":"'+$cipher+'"}'
    $r=$rc=$Null; $rc = try {$r = (post-command -url $url -body $body)} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($r.StatusCode -match '200') {$doFIPS2 = $False; $msg = "$time  SKIP - Cipherset $cipher already exists"; $msg; $msg >> $logfile }
    else {$doFIPS2 = $True}
  }  

  # Create FIPS2 cipher set
  if ($doFIPS2) {
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"modifycipherset","name":"'+$cipher+'","value":"'+$FIPS2+'"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -body $body)} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r.statuscode -eq 200) {$msg = "$time   SET - $Cipher CIPHER SET CREATED TO REMOVE WEAK FIPS ALGORITHMS"; $msg; $msg >> $logfile}
      else {$msg = "$time  ERR  - Error creating new cipher set ($Cipher)"; $msg; $msg >> $logfile}
  }
  start-sleep -Milliseconds 250
  
  # SETTING OUTBOUND CIPHER
  set-Param -ip $ip -port $port -APIKEY $apikey  -Param 'OutboundCipherset' -Value $cipher

  # SETTING INBOUND CIPHER
  Set-Param -ip $ip -port $port -APIKEY $apikey  -Param WUICipherset -value $cipher
  start-sleep -Milliseconds 500
  

  # Set LoadMaster hostname
  if ($doHostName) {set-param -ip $ip -port $port -apikey $apikey -param "hostname" -value $hostname }

  # Enable WUI Login Session Management
  set-param -ip $ip -port $port -apikey $apikey -Param sessioncontrol -value "yes"

  # Disable WUI Login Basic Authentication
  set-param -ip $ip -port $port -apikey $apikey -Param sessionbasicauth -value $False
  
  start-sleep -Milliseconds 250
  
  # Set WUI Session Idle TIme
  if ($WUI_IdleTime.length -ne 0) {set-param -ip $ip -port $port -apikey $apikey -param sessionidletime -value $WUI_IdleTime}
    
  # Set WUI Max Failed Logins before account lock
  if ($WUI_FailedLogins.length -ne 0) {set-param -ip $ip -port $port -apikey $apikey -param sessionmaxfailattempts -value $WUI_FailedLogins}
  
  # Set admin interface max concurrent logins (0 - unlimited)
  if ($WUI_MaxLogins -ne '') {set-param -ip $ip -port $port -apikey $apikey -param sessionconcurrent -value $WUI_MaxLogins}

  start-sleep -Milliseconds 250

  # Set USG WARNING BANNER FOR WUI Interface
  if ($doWarningBanners -and ($WUIMsg.Length -gt 0)) {set-param -ip $ip -port $port -apikey $apikey -param 'WUIPreauth' -value "$WUIMsg" }

  # Set USG WARNING BANNER FOR Console Interface
  if ($doWarningBanners -and ($ConsoleMsg.length -gt 0)) {set-param -ip $ip -port $port -apikey $apikey -param 'SSHPreAuth' -value "$ConsoleMsg" }

  # Disable Call Home
  if ($licenseinfo.MandatoryTether -ne 'yes')  {set-param -ip $ip -port $port -apikey $apikey -Param Tethering -Value 0}

  start-sleep -Milliseconds 250

  # Allows loadbalancing of servers located on a different subnet from the load balancer
  set-param -ip $ip -port $port -apikey $apikey -Param nonlocalrs -Value 'yes'

  # Required when LoadMaster is connected to 2 or more networks, optional when connected to 1 network
  if ($sor -ne '') {set-param -ip $ip -port $port -apikey $apikey -Param subnetorigin -Value $sor}

  # Disable SSL Renegotiation
  $isit=$Null; $isit = get-param -ip $ip -port $port -APIKey $apikey -param "sslrenegotiate"
  if (-not $isit ) {$msg = "$time  SKIP - SSL renegotiation already disabled"; $msg; $msg >> $logfile}
  else {set-param -ip $ip -port $port -APIKey $apikey -param "sslrenegotiate" -value 0} 

  start-sleep -Milliseconds 250

  # Force kerberos to use AES256 and SHA1
  set-param -ip $ip -port $port -apikey $apikey -Param "KcdCipherSha1" -Value 'yes'

  # Enable logs to use CEF data format
  set-param -ip $ip -port $port -apikey $apikey -Param "CEFMsgFormat" -Value 'yes'

  # Restict Web User Interface to TLS1.2 and TLS1.3
  set-param -ip $ip -port $port -apikey $apikey -Param "WUITLSProtocols" -Value "7"

  start-sleep -Milliseconds 250

  # Set TLS1.3 WUI Cipher Set  (space separated list)
  if (($LM_V -gt 56) -and (-not $FIPSMode)) {set-param -ip $ip -port $port -apikey $apikey -Param "WUITLS13Ciphersets" -Value "TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256"}

  start-sleep -Milliseconds 250

  ####################################################################
  ############### LOAD TLS CERTIFICATE (PEM format only) #############
  ####################################################################

  if ($doPEM) {
    $base64str = [convert]::ToBase64String((Get-Content -path "$certpath" -Encoding byte))
    [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"addcert", "cert":"'+$certname+'", "password":"'+$certpass+'", "replace":"0", "data":"'+$base64str+'"}'
    $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($r.code -eq '200') {$msg = "$time   SET - TLS Certificate ($certpath) installed as ($certname)"; $msg; $msg >> $logfile}
    else {$msg = "$time  SKIP - TLS Certificate ($certname) alredy installed"; $msg; $msg >> $logfile}
    start-sleep -Seconds 1
  }


  ##################################################
  # LOAD INTERMEDIATE CERTIFICATES (DER format only)
  ################################################## 
  if ($doCER) {
    foreach ($ica in $certlist) {
        [string]$icaname=$Null; [string]$icaname = (($ica.split("\")[-1]).split(".")[-2]).toupper()
        $base64str = [convert]::ToBase64String((Get-Content -path "$ica" -Encoding byte))
        [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"addintermediate", "replace" : "0", "cert":"'+$icaname+'", "data":"'+$base64str+'"}'
        $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
        if ($r.code -eq '200') {$msg = "$time   SET - Installed Intermediate Cert ($icaname)"; $msg; $msg >> $logfile}
        else {$msg = "$time  SKIP - Intermediate Certificate ($ica) already installed"; $msg; $msg >> $logfile}
    }
  start-sleep -Milliseconds 250
  }
  
  ##################################################
  # Assign Management Certificate to Admin Interface
  ##################################################
  if ($doAdminCert) {
    [string]$test=$Null; [string]$test = (get-param -ip $ip -port $port -APIKEY $apikey -param 'admincert').Replace("<Data>","").Replace("</Data>","")
    if ($test -ne $certname) {set-param -ip $ip -port $port -APIKEY $apikey -param admincert -value $certname}
    else {$msg = "$time  SKIP - admincert already set to ($certname)"; $msg; $msg >> $logfile}
    start-sleep -Milliseconds 250
  }

  ##################################################################
  # Assign Management Certificate to Local Interface (HA Pairs only)
  ##################################################################
  [bool]$doha = (Get-Param -ip $ip -port $port -APIKEY $apikey  -param 'hamode') -ne 0
  if ($doAdminCert -and $doha) {
    [string]$test=$Null; [string]$test = (get-param -ip $ip -port $port -APIKEY $apikey -param 'localcert').Replace("<Data>","").Replace("</Data>","")
    if ($test -ne "$certname") {set-param -ip $ip -port $port -APIKEY $apikey  -param localcert -value $certname}
    else {$msg = "$time  SKIP - localcert already set to ($certname)"; $msg; $msg >> $logfile}
    start-sleep -Milliseconds 250
  }

  #################
  # GEO Feature Set
  #################
  # Test if GEO included in support level
  if (-not ($EnableGEO.gettypecode() -match 'Boolean')) {$doGEO = $False}
  if ($licenseinfo.Option -match "GEO") {
    [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"isgeoenabled"}'
    $isgeo = (post-command -url $url -Body $body).content -match "GEO is enabled"
    if ($isgeo -ne $EnableGEO) {
      if ($EnableGEO) {[string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"enablegeo"}'}
      else {[string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"disablegeo"}'}
      if ($doGEO) {
        $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
        if ($r.code -eq '200') {$msg = "$time   SET - GEO service set to ($EnableGEO)"; $msg; $msg >> $logfile}
        else {$msg = "$time   ERR - Error configuring GEO service"; $msg; $msg >> $logfile}
      }
    }
    if ($isgeo -eq $EnableGEO) {$msg = "$time  SKIP - Current GEO state is ($isgeo) and desired state is ($EnableGEO)"; $msg; $msg >> $logfile}
  start-sleep -Milliseconds 250
  }

  ###############
  # Configure NTP
  ###############
  if ($doNTP) {
    $null = set-param -ip $ip -port $port -apikey $apikey -Param ntpkeysecret -value ""
  }
  if ($doNTPv3) {
    set-param -ip $ip -port $port -apikey $apikey -Param ntpkeytype -value "$NTPV3_KeyType"
    set-param -ip $ip -port $port -apikey $apikey -Param ntpkeyid -value "$NTPV3_KeyNum"
    set-param -ip $ip -port $port -apikey $apikey -Param ntpkeysecret -value "$NTPV3_Secret"
    set-param -ip $ip -port $port -apikey $apikey -Param ntphost -value "$NTP_Host"
    start-sleep -Milliseconds 250
  }
  if ($doNTP) {
    $msg = "$time  INFO - Setting NTP Host can take some time. Please be patient"; $msg 
    set-param -ip $ip -port $port -apikey $apikey -Param ntphost -value "$NTP_Host"
    start-sleep -Milliseconds 250
  }

  ###########################
  # Create LDAP Configuration 
  ###########################
  if ($doLDAP) {
    [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"showldapendpoint","name":"'+$LDAP_Name+'"}'
    $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($rc.code -eq 422) {
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"addldapendpoint","name":"'+$LDAP_Name+'","ldaptype":"'+$LDAP_Type+'","server":"'+$LDAP_Server+'","adminuser":"'+$LDAP_User+'","adminpass":"'+$LDAP_UserPass+'"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}

        if ($r.code -eq '200') {$msg = "$time   SET - Configured New LDAP service ($LDAL_Name)"; $msg; $msg >> $logfile}
        else {$msg = "$time   ERR - Error configuring LDAP service"; $msg; $msg >> $logfile}
      }
    Else {$msg = "$time  SKIP - LDAP Service ($LDAP_Name) already exists"; $msg; $msg >> $logfile}
  start-sleep -Milliseconds 250
  }

  ############################
  # Add Certificate based user
  ############################
  if ($doCertUser) {
    [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"usershow","user":"'+$NewCertUser+'"}'
    $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($rc.code -eq 422) {
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"useraddlocal","user":"'+$NewCertUser+'","nopass":"yes"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r.code -eq '200') {$msg = "$time   SET - Configured New Certificate Admin User ($NewCertUser)"; $msg; $msg >> $logfile}
      else {$msg = "$time   ERR - Error configuring New Certificate Admin User"; $msg; $msg >> $logfile}
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"usersetperms","user":"'+$NewCertUser+'","perms":"'+$newuserrights+'"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r.code -eq '200') {$msg = "$time   SET - Assigned rights ($newuserrights) to user ($NewCertUser)"; $msg; $msg >> $logfile}
      else {$msg = "$time   ERR - Error configuring rights for New Certificate Admin User ($newcertuser)"; $msg; $msg >> $logfile}
      }
    Else {$msg = "$time  SKIP - Certificate Admin User ($NewCertUser) already exists"; $msg; $msg >> $logfile}
  start-sleep -Milliseconds 250
  }

  #########################
  # Add Password based user
  #########################
  if ($doPassUser) {
    [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"usershow","user":"'+$NewPassUser+'"}'
    $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($rc.code -eq 422) {
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"useraddlocal","user":"'+$NewPassUser+'","password":"'+$NewPassUserPass+'"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r.code -eq '200') {$msg = "$time   SET - Configured New Password Admin User ($NewPassUser)"; $msg; $msg >> $logfile}
      else {$msg = "$time   ERR - Error configuring New Certificate Admin User"; $msg; $msg >> $logfile}
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"usersetperms","user":"'+$NewPassUser+'","perms":"'+$newuserrights+'"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r.code -eq '200') {$msg = "$time   SET - Assigned rights ($newuserrights) to user ($NewPassUser)"; $msg; $msg >> $logfile}
      else {$msg = "$time   ERR - Error configuring rights for New Password Admin User ($newPassuser)"; $msg; $msg >> $logfile}
      }
    Else {$msg = "$time  SKIP - Password Admin User ($NewPassUser) already exists"; $msg; $msg >> $logfile}
  start-sleep -Milliseconds 250
  }
  
  #################
  # Add Local Group
  #################
  if ($DoLDAPGroup) {
    [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"groupshow","group":"'+$NewUserGroup+'"}'
    $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($rc.code -eq 422) {
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"groupaddremote","group":"'+$NewUserGroup+'"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r.code -eq '200') {$msg = "$time   SET - Configured New LDAP Group ($NewUserGroup)"; $msg; $msg >> $logfile}
      else {$msg = "$time   ERR - Error configuring New LDAP Group ($NewUserGroup)"; $msg; $msg >> $logfile}
      [string]$body=$Null; [string]$body = '{"apikey":"'+$apikey+'","cmd":"groupsetperms","group":"'+$NewUserGroup+'","perms":"'+$newuserrights+'"}'
      $r=$rc=$Null; $rc = try {$r = (post-command -url $url -Body $body | convertfrom-json)} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r.code -eq '200') {$msg = "$time   SET - Assigned rights ($newuserrights) to user ($NewUserGroup)"; $msg; $msg >> $logfile}
      else {$msg = "$time   ERR - Error configuring rights for New Password Admin User ($newPassuser)"; $msg; $msg >> $logfile}
      }
    Else {$msg = "$time  SKIP - LDAP Group ($NewUserGroup) already exists"; $msg; $msg >> $logfile}
  start-sleep -Milliseconds 250
  }

  ###################
  # SET ADMIN GATEWAY
  ###################
  if (($admingw -eq $Null) -or ($admingw -match '')) {[string]$admingw = get-param -ip $ip -port $port -APIKEY $apikey -param dfltgw}
  set-param  -ip $ip -port $port -APIKEY $apikey -param admingw -value $admingw

  ###############################
  # Enable movement of default GW
  ###############################
  set-param -ip $ip -port $port -APIKey $apikey -param "multigw" -value 1

  #########################################################
  # Enable Web User Interface Certificate or Password Login 
  #########################################################
  if ($DoCertUser) {
    $r = get-param -ip $ip -port $port -APIKEY $apikey -param adminclientaccess
    if ($r -ne 1) {
      if ($LM_V -ge 58) {set-param -ip $ip -port $port -APIKEY $apikey -param adminclientaccess -value "1"}
      else {$lastmsg = $lastmsg = "`nCleanup for $ip. Please use WUI interface (Certificates & Security/Remote Access menu) and enable (Password or Client Certificate) login method.`n"}
    }
    else {$msg = "$time  SKIP - Admin Login Method already set to password or certificate"; $msg; $msg >> $logfile }
    start-sleep -Milliseconds 250
  }
}

#################
# END OF SCRIPT #
#################

if ($lastmsg.length -gt 0) {
  $msg = "`nREQUIRED MANUAL CONFIGURATION ITEMS (CLEANUP ACTIONS)"; Write-Host -fore cyan $msg; $msg >> $logfile
  write-host -fore yellow $lastmsg; $lastmessage >> $logfile
}

$msg = "`nSCRIPT COMPLETED"; Write-Host -fore cyan $msg; $msg >> $logfile

"################ END ##############" >> $logfile
 
###########################
# Clear sensitive variables
###########################
# Remove-Variable * -ErrorAction SilentlyContinue

###############
# Reset .curlrc
###############
if (Test-Path -Path "~\.oldcurlrc" -PathType leaf) {
Copy-Item -Path "~\.oldcurlrc" "~\.curlrc" -Force
Remove-Item -Path "~\.oldcurlrc" -Force
}


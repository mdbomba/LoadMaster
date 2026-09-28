# FIXES
# ADJUSTED FOR LINUX POWERSHELL 7.2 ENVIRONMENTS
# Added process to ensure API interface is enabled
# Fixed logic error when $doCER and/or $doPEM is set to $False
# Moved global standard variable declarations to top of script
# Removed dependency on Kemp PowerShell Module
# Removed dependency for a parameters file
# Converted to APIv1 calls (necessary for LMOS earlier than 7.2.54)
# Added function to create APIKEY for APIv1 calls
# Added function to set-param using APIv1 calls
# Added function to get-param using APIv1 calls
# Added function to ping a port
# Compensated for dirty response to get-param admincert
# Compensated for dirty response to get-param localcert
# Added Disable SSL Renegotiation 
# Added check for existing NTP Service and skip if already configured
# Added check for existing LDAP Service and skip if already configured
# Changed network check method to improve performance
# Added logic for no entry on parameters (skip associated sections)
# Added kerberos encryption requirements 
# Created custom cipher set FIPS2 to match our revised FIPS algorithm set
# Applied FIPS2 cipher set to management traffic
# Fixed bug in certificate admin user creation

###################################
# Cleanup and prepare to run script
###################################
clear-history
clear-host
Remove-Variable * -ErrorAction SilentlyContinue
[string]$ScriptVersion = "v3.20230209"
$Debug = $False

$psmajor = (get-host).version.major; $psminor = (get-host).version.minor
if ($psmajor -lt 7) {Write-Host "Requires PS Version 7 or newer. Terminating script"; return}
if ($psminor -lt 2) {Write-Host "Requires PS Version 7.2 or newer. Terminating script"; return}

############################
# STANDARD GLOBAL PARAMETERS 
############################          
$pattern1 = '^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
$pattern2 = '^(\d{1,4})$'
$wait = 250                                        ## Recommend you leave this value as is. 

#[string]$ConsoleMsg = "USG Warning Banner - YOU ARE ACCESSING A US GOVERNMENT (USG) INFORMATION SYSTEM PROVIDED FOR AUTHORIZED USE ONLY. Communications using, or data stored on this Information System are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any authorized purpose. USG logs all access to this system. Upon proper legal request, these logs and any other related data will be released for personnel misconduct and law enforcement purposes. Unauthorized use of this system will be prosecuted. By continuing to login, you agree to the above terms and conditions."

[string]$ConsoleMsg = "WARNING - NO CYBER TRESPASSING - VIOLATORS WILL BE PROSECUTED!"

[string]$WUIMsg = "<!DOCTYPE html><html><head><title>USG Warning Banner</title></head><style>p {color: black;}.title1 {font-size: 13px;text-align: center;}.paragraph1 {font-size: 12px; text-align: left;}</style><h1>USG WARNING AND CONSENT BANNER</h1><hr><p class=title1>YOU ARE ACCESSING A UNITED STATES GOVERNMENT (USG) INFORMATION SYSTEM<br>PROVIDED FOR AUTHORIZED USE ONLY</p><br><p class=paragraph1>By using this Information System (which includes any device attached to this Information System), you consent to the following conditions:<br><br>- USG routinely intercepts and monitors communications on this Information System for purposes including, but not limited to, penetration testing, network operations and defense, and upon proper legal request for personnel misconduct and law enforcement purposes.<br><br>- At any time, the USG may inspect and seize data stored on this Information System. Communications using, or data stored on this Information System are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any authorized purpose. This Information System includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.<br><br> - Notwithstanding the above, using this Information System does not constitute consent to legal or criminal investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. <br><br> - USG requires all USG personnel to complete Information System Security training annually.<br><br>- By continuing to login, you agree to the above terms and conditions.</p></body></html>"
[string]$FIPS2 = "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:AES128-GCM-SHA256:AES128-SHA256"

############### START OF CONFIGURATION PARAMETERS SECTION #############

[bool]$doFIPS2 = $True                                        # ENTER $True to Create restricted FIPS cipher set removing weak ciphers ($False to skip)
[bool]$doPassUser = $True                                     # ENTER $True to Create new admin account based on username and password ($False to skip)
[bool]$doCertUser = $True                             # ENTER $True to Create new admin account based on certificate principal name ($False to skip)
[bool]$doPEM = $True                                  # ENTER $True to Install management certificate (.pem file) ($False to skip)
[bool]$doAdminCert = $True                            # ENTER $True to Assign management certificate to WUI interface ($False to skip)
[bool]$doCer = $True                                  # ENTER $True to Install intermediate certificates (base64 .cer file) ($False to skip)
[bool]$doHostName = $True                             # ENTER $True to assign a hostname based on $hostbase + $IP ($False to skip)
[bool]$doNTP = $True                                  # ENTER $True to configure LoadMaster for NTP ($False to skip)
[bool]$doNTPv3 = $False                               # ENTER $True to if NTP service should use NTPv3 ($False to skip)
[bool]$doLdap = $False                                # ENTER $True to configure an LDAP service connection ($False to skip)
[bool]$doLdapGroup = $False                           # ENTER $True to configure an LDAP management group ($False to skip)
[string]$hostbase = 'vlm'                             # ENTER a name to create hostname prefix ('' will skip process)
[string]$NewCertUser = 'mike@kemptech.biz'            # ENTER a name to create a certificate login admin user ('' will skip process)
[string]$NewPassUser = 'mike-admin'                   # ENTER a name to create a name/password login admin user ('' will skip process)
[string]$NewPassUserPass = ''                         # Enter a password or leave blank to skip creating this user
[string]$NewUserGroup = ''                            # ENTER a name to LDAP admin group ('' will skip process)
[string]$NewUserRights = 'root'                       # ENTER rights for new user or group objects ('' will skip process)
[string]$sor = 'yes'                                  # ENTER 'yes' to enable Subnet Originating Request appliance wide ('' will skip process)
[string]$EnableGEO = 'no'                             # ENTER 'no' to disable GEO Loadbalancing Service ('yes' will enable service)
[string]$ntpv3_keynum = ''                            # ENTER NTPv3 Key Number ('' will skip process)
[string]$ntpv3_keytype = ''                           # ENTER NTPv3 Key Type ('' will skip process)
[string]$ntpv3_secret = ''                            # ENTER NTPv3 Key Secret ('' will skip process)
[string]$ntp_host = 'time.nist.gov'                   # ENTER NTP Server name or IP address ('' will skip process)
[string]$ldap_Name = ''                               # ENTER LDAP Service name or IP address ('' will skip process)
[string]$ldap_Server = ''                             # ENTER LDAP Server name or IP address ('' will skip process)
[string]$ldap_User = ''                               # ENTER LDAP Service Account Name ('' will skip process)
[string]$ldap_UserPass = ''                           # ENTER LDAP Service Account Password ('' will skip process)
[string]$ldap_Type = ''                               # ENTER LDAP Service Protocol ('' will skip process)
[string]$WUI_IdleTime = '600'                         # ENTER WUI Session Idle Logout Timer in seconds ('' will skip process)
[string]$WUI_FailedLogins = '5'                       # ENTER WUI Session Max Failed Logins ('' will skip process)
[string]$WUI_MaxLogins = '3'                          # ENTER WUI Session Max Concurrent Logins ('0' will not set a limit)
[string]$certpath = 'wildcard.pem'                    # ENTER PFX Certificate File ('' will skip process)
[string]$certpass = 'password'                        # ENTER PFX Certificate File Password = ##########"; if ($debug) {$msg}; $msg >> $logfile
[string]$certname = 'wildcard'                        # ENTER PFX Certificate File Name = " + $certname; if ($debug) {$msg}; $msg >> $logfile
[string]$ica1 = 'RSA.cer'                             # ENTER Intermediate Certificate File #1 = " + $ica1; if ($debug) {$msg}; $msg >> $logfile
[string]$ica2 = 'ECC.cer'                             # ENTER Intermediate Certificate File #1 = " + $ica1; if ($debug) {$msg}; $msg >> $logfile
[string]$ica3 = ''                                    # ENTER Intermediate Certificate File #3 = " + $ica3; if ($debug) {$msg}; $msg >> $logfile
[string]$ica4 = ''                                    # ENTER Intermediate Certificate File #4 = " + $ica4; if ($debug) {$msg}; $msg >> $logfile

[string]$workingDir = "."                             # If necessary, set this to a different location you have read/write rights

##### OPTIONAL PARAMETERS - IF ENTERED HERE WILL NOT BE PROMPTED FOR LATER #####
[array]$iplist = '10.0.0.33'
[string]$port = '443'
[string]$lmadmin = 'bal'
[string]$lmadminpass = ''
  
############## END OF CONFIGURATION SECTION #################

################ CHECK CONFIGURATION FILES ##################
if ($certpath.length -gt 0) {if (-not (test-path -path $certpath -PathType Leaf)) {$certpath = ''; $doPEM = $False}}
if ($ica4.length -gt 0) {if (-not (test-path -path $ica4 -PathType Leaf)) {$ica4 = ''}}
if ($ica3.length -gt 0) {if (-not (test-path -path $ica3 -PathType Leaf)) {$ica3 = ''}}
if ($ica2.length -gt 0) {if (-not (test-path -path $ica2 -PathType Leaf)) {$ica2 = ''}}
if ($ica1.length -gt 0) {if (-not (test-path -path $ica1 -PathType Leaf)) {$ica1 = ''}}
if (($ica1 -eq '') -and ($ica2 -eq '') -and ($ica3 -eq '') -and ($ica4 -eq '')) {$doCER = $False; $doCertUser = $False}

########################
# Provide info on script
########################
$msg = "SCRIPT TO APPLY STIG SETTINGS TO LOADMASTER"; Write-Host -Fore cyan $msg; $msg >> $logfile

# Prompt for LoadMaster admin account
if ($lmadmin.length -eq 0) {
  do {
   $lmAdmin = Read-Host -Prompt "Enter LoadMaster Amin Account (e.g. bal)"
  } while ($lmAdmin.length -lt 1)
}

# Prompt for LoadMaster admin password
if ($lmadminpass.Length -eq 0) {
  do {
   "Enter password for $lmadmin in secure popup box"
   $Pass = Read-Host "ENTER PASSWORD for $lmadmin" -AsSecureString 
   $Pass = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Pass)
   $lmAdminPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Pass)
  } while ($lmAdminPass.length -lt 8)
}

# Prompt for LoadMaster WUI Port
if ($port.length -eq 0) {do {$port = read-host -Prompt "Enter LoadMaster WUI Port (e.g. 443 or 8443)"} while ($port.length -lt 1) }

# Prompt for a list of LoadMaster WUI IP addresses
if (($iplist.count -eq 0) -or ($iplist[0].length -lt 5)) {
  do {
    $ip = read-host -Prompt "Enter all LoadMaster WUI IP Addresses (blank line to finish)"
    if ($ip -match $pattern1) {$iplist += $ip} 
    ElseIF ($ip -ne "") {"ERROR IN IP ADDRESS FORMAT"}
  } while ($ip -ne '')
  $iplist = $iplist.Where({ $_ -ne "" })
}

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
"################ START ##############" >> $logfile
$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Working directory ($workingdir)"; $msg; $msg >> $logfile

###############################################
# Function to Ping a Port with variable timeout
###############################################
function Test-Port ($ip, $port, $Timeout) {
-not (test-connection -computername $ip -TcpPort $port)
}


###################################
# DEFINE FUNCTION TO COLLECT APIKEY
###################################
# APIKEY can only be generated AFTER LoadMaster is licensed
function get-apikey ($ip, $port, $Credential) {
[string]$url = "https://$ip"+':'+"$port/access/addapikey"
$rc = try {$r = Invoke-WebRequest -SkipCertificateCheck -Method Get -Uri $url -Credential $Credential} catch {'{"code":"422"}' | ConvertFrom-Json}
$res = $r.RawContent.tostring()
$start = $res.indexof('<key>') + 5
$end  = $res.indexof('</key>')
$apikey = $res.substring($start, ($end - $start))
$apikey
}
######################################################################################

##########################################################
# CREATE FUNCTION TO SET PARAMETERS USING DIRECT API CALLS
##########################################################
FUNCTION set-param ($ip, $port, $param, $value, $APIKEY) {
  # Function assumes $lmadmin, $lmadminpass, $ip, and $port values are already set
  $p = $param.ToLower(); $v = $value.ToLower()
  if (test-path -Path $logfile -PathType leaf) {$log = $logfile} Else {$log = '$Null'}
  $val_length = $v.tostring().length; if ($val_length -gt 20) {$val_length = 20}
  $val = $value.tostring().substring(0,$val_length)
  [string]$url = "https://$ip"+':'+"$port/access/get?apikey=$apikey&param=$param"
  $rc = try {$r = ((Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).rawcontent).tostring().tolower()} catch {'{"code":"422"}' | ConvertFrom-Json}
  if ($rc.code -ne 422) {
    [int]$p_length = $p.length + 2
    [int]$start = $r.indexof("<$p>") + $p_length
    [int]$end = $r.indexof("</$p>")
    $asis = $r.Substring($start, ($end-$start))
    if ($asis -ne $v) {
      [string]$url = "https://$ip"+':'+"$port/access/set?apikey=$apikey&param=$param&value=$value"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq '200') {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Successfully set ($param) to ($val)"; $msg; $msg >> $log}
      Else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  FAIL - Failed to set ($param) to ($val)"; $msg; $msg >> $log}
    }
    Else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Parameter ($param) set to ($val)"; $msg; $msg >> $log}
  }
  Else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Cannot set Parameter ($param)"; $msg; $msg >> $log}
    
    start-sleep -Milliseconds 250
}
##########################################################

##########################################################
# CREATE FUNCTION TO GET PARAMETERS USING DIRECT API CALLS
##########################################################
function Get-Param ($ip, $port, $param, $APIKEY) {
  # Function assumes $lmadmin, $lmadminpass, $ip, and $port values are already set
  $param = $param.ToLower()
  [string]$url = "https://$ip"+':'+"$port/access/get?apikey=$apikey&param=$param"
  $rc = try {$r = ((Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).rawcontent).tostring().ToLower()} catch {'{"code":"422"}' | ConvertFrom-Json}
  [int]$p_length = $param.length + 2
  [int]$start = $r.indexof("<$param>") + $p_length
  [int]$end = $r.indexof("</$param>")
  $asis = $r.Substring($start, ($end-$start))
  $val_length = $asis.tostring().length; if ($val_length -gt 20) {$val_length = 20}
  $val = $asis.tostring().substring(0,$val_length)
  $val
}

#########################
# Build credential object 
#########################
$creds = $Null; $creds = New-Object pscredential("$lmadmin", (ConvertTo-SecureString -String "$lmadminpass" -AsPlainText -Force))  

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

###########################################
# Populate $certlist for intermediate certs
###########################################
if ($doCER) {
  [array]$certlist = $Null
  if ($ica1 -ne '') {if (test-path -path $ica1 -pathtype leaf) {$certlist += $ica1}}
  if ($ica2 -ne '') {if (test-path -path $ica2 -pathtype leaf) {$certlist += $ica2}}
  if ($ica3 -ne '') {if (test-path -path $ica3 -pathtype leaf) {$certlist += $ica3}}
  if ($ica4 -ne '') {if (test-path -path $ica4 -pathtype leaf) {$certlist += $ica4}}
  $certlist = $certlist.Where({ $_ -ne "" })
}
if ($certlist.count -eq 0) {$doCER = $False}

################################
# Process all entries in $iplist
################################
$ip = $Null
foreach ($ip in $iplist) {

  $msg = "STARTING CONFIGURATION FOR $IP"; Write-Host -fore cyan $msg; $msg >> $logfile

  [string]$ipport = $ip + ":" + $Port
  [string]$hostname = $hostbase + '-' + $ip.split('.')[-1]
  
  ############################################
  # Test connectivity and skip entry as needed
  ############################################
  $rc = test-port -ip $ip -port $port
  if ($rc) {$msg =  (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - SKIPPING PROCESSING FOR $IP - CANNOT CONNECT"; $msg; $msg >> $logfile ; continue}

  #################################
  # ENSURE API INTERFACE IS ENABLED
  #################################
  $Uri = "https://$ipport/access/set?Param=enableapi&Value=yes"
  $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method get -Uri $uri -Credential $creds)} catch {'{"code":"422"}' | ConvertFrom-Json}
  if ($r.content -match "<Success>Command completed ok</Success>") {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - API Interface is enabled"; $msg; $msg >> $logfile }
  else { $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - CANNOT DETERMINE API STATE, SKIPPING $IP"; $msg; $msg >> $logfile }

  ######################
  # Build API auth token
  ######################
  $apikey = $Null; $apikey = get-apikey -ip $ip -port $port -Credential $creds

  ##############################
  # Collect data from LoadMaster
  ##############################
  [array]$allapi =$Null; $allapi = @(Invoke-WebRequest -SkipCertificateCheck -Uri "https://$ipport/access/listapi" -Method get -Credential $creds).rawcontent
  [string]$allparams = $Null; $allparams = @(Invoke-WebRequest -SkipCertificateCheck -Uri "https://$ipport/access/getall" -Method get -Credential $creds).rawcontent
  $allapi > t.txt; $allapi = $Null; [string]$allapi = cat t.txt; del t.txt
  $allparams > t.txt; $allparams = $Null; [string]$allparams = cat t.txt | Sort-Object; del t.txt
  $allapi = $allapi.split(' ').trimstart('<cmd>').trimend('</cmd>') | Sort-Object
  ###############################################
  # VALIDATE INFO NEEDED FOR OPTIONS IS AVAILABLE
  ###############################################
    
  #######################################################
  # Check for minimum LoadMaster Operating System version
  #######################################################
  [string]$LM_R = "48"
  [string]$LM_V = (get-param -ip $ip -port $port -APIKEY $apikey -param "version").tostring().Split(".")[2]

  if ($LM_V -ge $LM_R) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - LoadMaster LMOS validation PASSED"; $msg; $msg >> $logfile }
  else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - PROCESSING FOR LOADMASTER $IP (LMOS validation FAILED)."; $msg; $msg >> $logfile; return } 
  start-sleep -Milliseconds 250
 
  ##########################
  # Create FIPS++ Cipher Set
  ##########################
  if ($doFIPS2) {
    $rc = $r = $Null
    [string]$cipher = 'FIPS2'
    [string]$url = "https://$ipport/access/getcipherset?name=$cipher"
    $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $url -Credential $creds)} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($r.StatusCode -match '200') {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Cipherset $cipher already exists"; $msg; $msg >> $logfile }
    Else {
      [string]$url = "https://$ipport/access/modifycipherset?name=$cipher&value=$FIPS2"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $url -Credential $creds).rawcontent} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -match 'stat="200"') {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SET  - $Cipher CIPHER SET CREATED TO REMOVE WEAK FIPS ALGORITHMS"; $msg; $msg >> $logfile}
      else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Error creating new cipherser ($Cipher)"; $msg; $msg >> $logfile}
    }
    start-sleep -Milliseconds 250
  }
  else {[string]$cipher = 'FIPS'}

  # SETTING OUTBOUND CIPHER TO FIPS++
  set-Param -ip $ip -port $port -APIKEY $apikey  -Param 'OutboundCipherset' -Value $cipher

  # SETTING INBOUND CIPHER TO FIPS++
  Set-Param -ip $ip -port $port -APIKEY $apikey  -Param WUICipherset -value $cipher

  start-sleep -Milliseconds 250

  # Set LoadMaster hostname
  if ($DoHostName) {set-param -ip $ip -port $port -APIKEY $apikey  -param "hostname" -value $hostname }

  # Enable WUI Login Session Management
  set-param -ip $ip -port $port -APIKEY $apikey  -Param sessioncontrol -value "yes"

  start-sleep -Milliseconds 250

  # Disable WUI Login Basic Authentication
  $r = get-param -ip $ip -port $port -APIKEY $apikey  -param sessionbasicauth
  if ($r -eq $false) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Parameter (sessionbasicauth) already set to (no)"; $msg; $msg >> $logfile}
  else {set-param -ip $ip -port $port -APIKEY $apikey  -Param sessionbasicauth -value "no"}
  
  # Set admin interface logout on idle timer
  if ($WUI_IdleTime -ne '') {set-param -ip $ip -port $port -APIKEY $apikey  -param sessionidletime -value $WUI_IdleTime}

  start-sleep -Milliseconds 250

  # Set admin interface failed login to lock account limit
  if ($WUI_FailedLogins -ne '') {set-param -ip $ip -port $port -APIKEY $apikey  -param sessionmaxfailattempts -value $WUI_FailedLogins}

  # Set admin interface max concurrent logins (0 - unlimited)
  if ($WUI_MaxLogins -ne '') {set-param -ip $ip -port $port -APIKEY $apikey  -param sessionconcurrent -value $WUI_MaxLogins}

  start-sleep -Milliseconds 250
  ##########################################
  # Set USG WARNING BANNER FOR Web Interface
  ##########################################
  if ($WUIMsg.Length -gt 5) {
    $test = get-param -ip $ip -port $port -APIKEY $apikey -param 'WUIPreauth'
    if ($test.Length -lt 5) {
      $postParams = @{apikey="$apikey";param="WUIPreauth";value="$WUIMsg"}
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Post -Body $postParams -uri "https://$ipport/access/set").baseResponse.StatusCode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq "OK") {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Setting WUI warning banner"; $msg; $msg >> $logfile}
      else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Set WUI warning banner"; $msg; $msg >> $logfile}
    }
    else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - WUI warning banner already configured"; $msg; $msg >> $logfile}
    start-sleep -Milliseconds 250
  }

  # Set USG WARNING BANNER FOR Console Interface
  if ($ConsoleMsg.length -gt 5) {
    $test = get-param -ip $ip -port $port -APIKEY $apikey -param 'SSHPreAuth'
    if ($test.Length -lt 5) {
      $postParams = @{apikey="$apikey";param="SSHPreAuth";value="$ConsoleMsg"}
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Post -Body $postParams -uri "https://$ipport/access/set").baseResponse.StatusCode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq "OK") {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Setting Console warning banner"; $msg; $msg >> $logfile}
      else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Set Console warning banner"; $msg; $msg >> $logfile}
    }
    else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Console warning banner already configured"; $msg; $msg >> $logfile}
    start-sleep -Milliseconds 250
  }

  # Disable Call Home
  Set-Param -ip $ip -port $port -APIKEY $apikey  -Param Tethering -Value "no"

  # Allows loadbalancing of servers located on a different subnet from the load balancer
  Set-Param -ip $ip -port $port -APIKEY $apikey  -Param nonlocalrs -Value 'yes'

  start-sleep -Milliseconds 250

  # Required when LoadMaster is connected to 2 or more networks, optional when connected to 1 network
  if ($sor -ne '') {Set-Param -ip $ip -port $port -APIKEY $apikey -Param subnetorigin -Value $sor}

  # Disable SSL Renegotiation
  $isit = get-param -ip $ip -port $port -APIKEY $apikey  -param sslrenegotiate;
  if ($isit -eq $True) {Set-Param -ip $ip -port $port -APIKEY $apikey  -param "sslrenegotiate" -value 0}
  Else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Parameter (sslrenegotiate) already set to (no)"; $msg; $msg >> $logfile}

  start-sleep -Milliseconds 250

  # Force kerberos to use AES256 and SHA1
  Set-Param -ip $ip -port $port -APIKEY $apikey  -Param "KcdCipherSha1" -Value 'yes'

  # Enable logs to use CEF data format
  if ($LM_V -ge 54) {Set-Param -ip $ip -port $port -APIKEY $apikey  -Param "CEFMsgFormat" -Value 'yes'}

  start-sleep -Milliseconds 250

  # Restict Web User Interface to TLS1.2 and TLS1.3
  Set-Param -ip $ip -port $port -APIKEY $apikey -Param "WUITLSProtocols" -Value "7"

  # Set TLS1.3 WUI Cipher Set  (space separated list)
  if ($LM_V -gt 56) {Set-Param -ip $ip -port $port -APIKEY $apikey  -Param "WUITLS13Ciphersets" -Value "TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256"}

  start-sleep -Milliseconds 250

  ############### LOAD TLS CERTIFICATE (PEM format only) #############
  if ($doPEM) {
    $r = $rc = $Null
    [string]$url = "https://$ipport/access/listcert?cert=$certname"
    $rc = try {$r = Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $url -Credential $creds} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($rc.code -match '(422)') {[bool]$doit = $False; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Command Failed"; $msg; $msg >> $logfile}
    if (($r.StatusCode -eq '200') -and ($r -match "<name>$certname</name>")) {[bool]$doit = $false; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Certificate already installed ($certname)"; $msg; $msg >> $logfile}
    else {[bool]$doit = $True}
    if ($doit) {
      $r = $rc = $Null
      [string]$url = "https://$ipport/access/addcert?cert=$certname&password=$certpass&replace=0"
      $rc = try {$r = Invoke-WebRequest -SkipCertificateCheck -uri $url -Method Post -Infile $certpath -ContentType 'multipart/form-data' -Credential $creds} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($rc.code -match '(422)') {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Command Failed"; $msg; $msg >> $logfile}
      if ($r.statuscode -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Installed ($certname)"; $msg; $msg >> $logfile}
    }
  start-sleep -Seconds 1
  } 

  ##################################################
  # LOAD INTERMEDIATE CERTIFICATES (DER format only)
  ################################################## 
  if ($doCER) {
    foreach ($ica in $certlist) {
      [string]$base_file = ($ica.split("\")[-1])
      [string]$file = $workingDir + '\' + $base_file
      [string]$name = ($base_file.split(".")[-2]).toupper()
      $rc = $r = $Null
      [string]$url = "https://$ipport/access/listintermediate"
      $rc = try {$r = Invoke-WebRequest -SkipCertificateCheck -Method Post -uri $url -Infile $file -ContentType 'multipart/form-data' -Credential $creds} catch {'422'}
      $r.RawContent > t.txt; $asis_cer = $Null; [string]$asis_cer = cat t.txt; del t.txt
      if ($asis_cer -notmatch "<name>$name</name") {
      $rc = $r = $Null
      [string]$url = "https://$ipport/access/addintermediate?cert=$name&replace=0"
      $rc = try {$r = Invoke-WebRequest -SkipCertificateCheck -Method Post -uri $url -Infile $file -ContentType 'multipart/form-data' -Credential $creds} catch {'422'}
      if ($rc -ne '422') {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SET  - Intermediate Certificate LOADED ($name)"; $msg; $msg >> $logfile}
      else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Cannot load Intermediate Certificate ($name)"; $msg; $msg >> $logfile}
      }
      else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Intermediate Certificate ALREADY LOADED ($name)"; $msg; $msg >> $logfile}
    }
    start-sleep -Milliseconds 250
  }

  ##################################################
  # Assign Management Certificate to Admin Interface
  ##################################################
  if ($doAdminCert) {
    $o=$s=$e=$l=$r=$Null
    $uri = "https://$ipport/access/get?param=admincert"
    $o = ((Invoke-WebRequest -SkipCertificateCheck -uri $uri -Method Get -Credential $creds).content).tostring()
    [int]$s = $o.indexof('<admincert>') + 11
    [int]$e = $o.indexof('</admincert>')
    [int]$l = $e - $s
    $r = (($o.substring($s, $l)) -replace '[\W]', '').trimstart('60Data62').trimend('60Data62')
    $test = $r
    $o=$s=$e=$l=$r=$Null
    if ($test -ne $certname) {set-param -ip $ip -port $port -APIKEY $apikey -param admincert -value $certname}
    else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - admincert already set to ($certname)"; $msg; $msg >> $logfile}
    start-sleep -Milliseconds 250
  }

  ##################################################################
  # Assign Management Certificate to Local Interface (HA Pairs only)
  ##################################################################
  if ($doAdminCert) {
    if (-not $allparams.contains('<hamode>0</hamode>')) {
      $o=$s=$e=$l=$r=$Null; $test = 'nolocalcertificateassigned'
      $uri = "https://$ipport/access/get?param=localcert"
      $o = ((Invoke-WebRequest -SkipCertificateCheck -uri $uri -Method Get -Credential $creds).content).tostring()
      if ($o -ne $Null) {
        [int]$s = $o.indexof('<admincert>') + 11
        [int]$e = $o.indexof('</admincert>')
        [int]$l = $e - $s
        $r = (($o.substring($s, $l)) -replace '[\W]', '').trimstart('60Data62').trimend('60Data62')
        $test = $r
        $o=$s=$e=$l=$r=$Null
      }
      if ($test -ne $certname) {set-param -ip $ip -port $port -APIKEY $apikey -param localcert -value $certname}
      else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - admincert already set to ($certname)"; $msg; $msg >> $logfile}
    }
    start-sleep -Milliseconds 250
  }

  #################
  # GEO Feature Set
  #################
  if ($EnableGEO -ne '') {
    # Test if GEO included in support level
    $uri = "https://$ipport/access/licenseinfo?apikey=$apikey"
    $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $uri).rawcontent} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($r -match '<Name>Standard</Name>') {$licgeo = $False} else {$licgeo = $True}
    if ($licGEO) {
      $rc = $r = $Null
      $uri = "https://$ipport/access/isgeoenabled?apikey=$apikey"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Post -uri $uri).rawcontent} catch {'{"code":"422"}' | ConvertFrom-Json}
      $isgeo = ($r -match '<Data>GEO is enabled</Data>')
      if ($doGEO -eq $isgeo) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - GEO is already set to "+$doGEO; $msg; $msg >> $logfile}
      if ($doGEO -and (-not $isgeo)) {
        $rc = $r = $Null
        $uri = "https://$ipport/access/enablegeo?apikey=$apikey"
        $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $uri).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
        if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SET  - Enable GEO Feature Set"; $msg; $msg >> $logfile}
        else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Enable GEO Feature Set"; $msg; $msg >> $logfile}
      }
      if ((-not $doGEO) -and $isgeo) {
        $rc = $r = $Null
        $uri = "https://$ipport/access/disablegeo?apikey=$apikey"
        $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $uri).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
        if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SET  - Disable GEO Feature Set"; $msg; $msg >> $logfile}
        else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Disable GEO Feature Set"; $msg; $msg >> $logfile}
      }
    }
    start-sleep -Milliseconds 250
  }

  ###############
  # Configure NTP
  ###############
  if ($doNTP) {
    $null = Set-Param -ip $ip -port $port -APIKEY $apikey -Param ntpkeysecret -value ""
  }
  if ($doNTPv3) {
    Set-Param -ip $ip -port $port -APIKEY $apikey -Param ntpkeytype -value "$NTPV3_KeyType"
    Set-Param -ip $ip -port $port -APIKEY $apikey -Param ntpkeyid -value "$NTPV3_KeyNum"
    Set-Param -ip $ip -port $port -APIKEY $apikey -Param ntpkeysecret -value "$NTPV3_Secret"
    Set-Param -ip $ip -port $port -APIKEY $apikey -Param ntphost -value "$NTP_Host"
    start-sleep -Milliseconds 250
  }
  if ($doNTP) {
    $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Setting NTP Host can take some time. Please be patient"; $msg 
    Set-Param -ip $ip -port $port -APIKEY $apikey -Param ntphost -value "$NTP_Host"
    start-sleep -Milliseconds 250
  }

  

  ###########################
  # Create LDAP Configuration 
  ###########################
  if ($doLDAP) {
    $rc = $r = $Null
    $url = "https://$ipport/access/showldapendpoint?apikey=$apikey&name=$LDAP_Name"
    $rc = try {$r = Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($rc.code -notmatch "422") {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - LDAP Endpoint ($LDAP_Name) already exists"; $msg; $msg >> $logfile}
    Else {
    $rc = $r = $Null
    $url = "https://$ipport/access/addldapendpoint?apikey=$apikey&name=$LDAP_Name&ldaptype=$LDAP_Type&server=$LDAP_Server&adminuser=$LDAP_User&adminpass=$LDAP_UserPass"
    $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($r -match '200') {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Created LDAP Endpoint ($LDAP_Name)"; $msg; $msg >> $logfile}
    Else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Error creating LDAP Endpoint ($LDAP_Name)"; $msg; $msg >> $logfile}
    }
    start-sleep -Milliseconds 250
  }

  ############################
  # Add Certificate based user
  ############################
  if ($doCertUser) {
    $rc = $r = $Null
    $url = "https://$ipport/access/userlist?apikey=$apikey"
    $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).rawcontent} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($r -notmatch "<Name>$newcertuser</Name>") {$doit = $True} Else  {$doit = $False}
    if (-not $doit) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - User ($newcertuser) already exists"; $msg; $msg >> $logfile}
    if ($doit) {
      $rc = $r = $Null
      $url = "https://$ipport/access/useraddlocal?apikey=$apikey&nopass=yes&user=$newcertuser"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Created user ($newcertuser)"; $msg; $msg >> $logfile}
      else {$doit = $False; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Create user ($newcertuser)"; $msg; $msg >> $logfile}
    }
    if ($doit) {
      $rc = $r = $Null
      $url = "https://$ipport/access/usersetperms?apikey=$apikey&nopass=yes&user=$newcertuser&perms=$newuserrights"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Assigned rights to user ($newcertuser)"; $msg; $msg >> $logfile}
      else {$doit = $False; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Assign rights to user ($newcertuser)"; $msg; $msg >> $logfile}
    }
  start-sleep -Milliseconds 250
  }

  #########################
  # Add Password based user
  #########################
  if ($doPassUser) {
    $rc = $r = $Null
    $url = "https://$ipport/access/userlist?apikey=$apikey"
    $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).rawcontent} catch {'{"code":"422"}' | ConvertFrom-Json}
    if ($r -notmatch "<Name>$newpassuser</Name>") {$doit = $True} Else  {$doit = $False}
    if (-not $doit) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - User ($newpassuser) already exists"; $msg; $msg >> $logfile}
    if ($doit) {
      $rc = $r = $Null
      $url = "https://$ipport/access/useraddlocal?apikey=$apikey&user=$newpassuser&password=$newpassuserpass"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Created user ($newpassuser)"; $msg; $msg >> $logfile}
      else {$doit = $False; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Create user ($newpassuser)"; $msg; $msg >> $logfile}
    }
    if ($doit) {
      $rc = $r = $Null
      $url = "https://$ipport/access/usersetperms?apikey=$apikey&user=$newpassuser&perms=$newuserrights"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get  -uri $url).statuscode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Assigned rights to user ($newpassuser)"; $msg; $msg >> $logfile}
      else {$doit = $False; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Assign rights to user ($newpassuser)"; $msg; $msg >> $logfile}
    }
  start-sleep -Milliseconds 250
  }
  
  
  
  #################
  # Add Local Group
  #################
  if ($DoLDAPGroup) {
    $rc = $r = $Null
    $url = "https://$ipport/access/grouplist?apikey=$apikey"
    $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $url).RawContent.ToString()} catch {'{"code":"422"}' | ConvertFrom-Json}
    $doit = ($r -notmatch "<Name>$newUserGroup</Name>")
    if ($doit) {
      $rc = $r = $Null
      $url = "https://$ipport/access/groupaddremote?apikey=$apikey&group=$newUserGroup"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $url).StatusCode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Created user group ($newusergroup)"; $msg; $msg >> $logfile}
      else {$doit = $False; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Create user group ($newusergroup)"; $msg; $msg >> $logfile}

      $rc = $r = $Null
      $url = "https://$ipport/access/groupsetperms?apikey=$apikey&group=$newUserGroup&perms=$newUserRights"
      $rc = try {$r = (Invoke-WebRequest -SkipCertificateCheck -Method Get -uri $url).StatusCode} catch {'{"code":"422"}' | ConvertFrom-Json}
      if ($r -eq 200) {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  INFO - Assigned rights to new user group ($newusergroup)"; $msg; $msg >> $logfile}
      else {$doit = $False; $msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  ERR  - Failed to Assigned rights to new user group ($newusergroup)"; $msg; $msg >> $logfile}
    }
    Else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Group ($newUserGroup) already exists"; $msg; $msg >> $logfile}
  start-sleep -Milliseconds 250
  }

  #########################################################
  # Enable Web User Interface Certificate or Password Login 
  #########################################################
  if ($DoCertUser) {
    $r = get-param -ip $ip -port $port -APIKEY $apikey -param adminclientaccess
    if ($r -ne 1) {
      if ($LM_V -ge 58) {set-param -ip $ip -port $port -APIKEY $apikey -param adminclientaccess -value "1"}
      else {$lastmsg = $lastmsg = "`nCleanup for $ip. Please use WUI interface (Certificates & Security/Remote Access menu) and enable (Password or Client Certificate) login method.`n"}
    }
    else {$msg = (Get-Date -Format "yyyy/MM/dd HH:mm") + "  SKIP - Admin Login Method already set to password or certificate"; $msg; $msg >> $logfile }
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
#Remove-Variable * -ErrorAction SilentlyContinue

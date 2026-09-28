clear-host
clear-history

<#LoadMaster initial Setup with a CSV file through powershell

    .NOTES

    Version:    1.2
    Author:     Renard Schöpfel
    Date:       2022-Aug
    Changes:
    add notes& comments
    #>

# leave blank "" if you want to be prompted for info
[string]$KempID = "" 
if ($KempID -eq "") {[string]$KempID = read-host -Prompt "Enter your KempID used for licensing"}

# leave blank "" if you want to be prompted for info
[string]$KempIDPass = ""
if ($KempIDPass -eq "") {[string]$KempIDPass = read-host -Prompt "Enter the password for your KempID"}

# leave blank "" if you want to be prompted for info
[string]$newLMpass = ""
if ([string]$newLMpass -eq "") {[string]$newLMpass = read-host -Prompt "Enter new password for bal account"}

# leave blank "" if you want to be prompted for info
[string]$oldLMpass = ''
if ([string]$oldLMpass -eq "") {[string]$oldLMpass = read-host -Prompt "Enter current password for bal account"}

#Import of the CSV file to get access to the parameters
#load parameters from each line in the file

Import-Csv -Path .\Parameters.csv | ForEach-Object {
  [string]$OrderID = ($_.OrderID)
  [string]$loadbalancer = ($_.loadbalancer)
  [string]$LBPort = ($_.LBPort)
  [string]$hostname = ($_.hostname)
  [string]$dfltgw = ($_.dfltgw)
  [string]$ntphost = ($_.ntphost)
  [string]$timezone = ($_.timezone)
  [string]$DNS1 = ($_.DNS1)
  [string]$DNS2 = ($_.DNS2)
  [string]$searchlist = ($_.searchlist)
  [string]$wuiidletime = ($_.wuiidletime)
  [string]$HAMode = ($_.HAMode)
  [string]$HAID = ($_.HAID)
  [string]$ETH0 = ($_.ETH0)
  [string]$PaETH0 = ($_.PaETH0)
  [string]$ShdETH0 = ($_.ShdETH0)
  [string[]]$ETH = $Null
            $ETH += ($_.ETH0)
            $ETH += ($_.ETH1)
            $ETH += ($_.ETH2)
  [string[]]$PaETH = $Null
            $PaETH += ($_.PaETH0)
            $PaETH += ($_.PaETH1)
            $PaETH += ($_.PaETH2)
  [string[]]$ShdETH = $Null
            $ShdETH += ($_.ShdETH0)
            $ShdETH += ($_.ShdETH1)
            $ShdETH += ($_.ShdETH2)
  [string]$LdapEndpoint = ($_.LdapEndpoint)
  [string]$LdapServer = ($_.LdapServer)
  [string]$LdapProtocol = ($_.LdapProtocol)
  [string]$LdapUser = ($_.LdapUser)
  [string]$LdapUserpass = ($_.LdapUserPass)
  [string]$WUIUserGroup = ($_.WUIUserGroup)
  [string]$WUIUserGroupPerm = ($_.WUIUserGroupPerm)
  [string]$certname = ($_.certname)
  [string]$certpath = ($_.certpath)
  [string]$certpass = ($_.certpass)
  [string]$localcertname = ($_.localcertname)
  [string]$localcertpath = ($_.localcertpath)
  [string]$localcertpass = ($_.localcertpass)


# Each parameter is defined as an object with properties
# Param is the name of the parameter
# Value is the value for the parameter
# For a list of supported parameters see
# https://kemptechnologies.github.io/powershell-sdk-vnext/ps-help.html#Set-LmParameter

$LMParameters = @(
@{Param = 'Hostname' ; Value = $hostname }
@{Param = 'ntphost' ; Value = $ntphost }
@{Param = 'timezone' ; Value = $timezone }
@{Param = 'Dfltgw' ; Value = $dfltgw }
@{Param = 'searchlist' ; Value = $searchlist }
@{Param = 'nameserver' ; Value = $DNS1 }
@{Param = 'nameserver' ; Value = $DNS2 }
@{Param = 'DNSNamesEnable' ; Value = 1 }
)

# Each loadmaster is an object
# The connection property is an object with the connection parameters
# to connect to the LoadMaster during configuration
# LoadBalancer contain the network address of the LoadMaster to configure
# LBPort is the port to connection to, normally 443
# The NetworkInterfaces property is an array of objects
# containing the network interfaces to configure

$loadBalancers = @(
@{Connection = @{LoadBalancer = $Loadbalancer ; LBPort = $LBPort } }
)

################################
#STARTING CONFIGURATION PROCESS#
################################
write-host -fore cyan "`nSTARTING CONFIGURATION PROCESS - $loadbalancer"
write-host -fore cyan "THE FOLLOWING ARE A LIST OF PARAMETERS EXTRACTED FROM PARAMETERS.CSV FILE"
write-host '$OrderID = '$OrderID
write-host '$loadbalancer = '$loadbalancer
write-host '$LBPort = '$LBPort
write-host '$DNS = '$DNS
write-host '$searchlist = '$searchlist
write-host '$wuiidletime = '$wuiidletime
write-host '$HAMode = '$HAMode
write-host '$ETH INFO'
$ETH
write-host '$PaETH INFO'
$PaETH
write-host '$ShdETH INFO'
$ShdETH
write-host '$LdapEndpoint = '$LdapEndpoint
write-host '$LdapServer = '$LdapServer
write-host '$LdapProtocol = '$LdapProtocol
write-host '$LdapUser = '$LdapUser
write-host '$LdapUserpass = '$LdapUserpass
write-host '$WUIUserGroup = '$WUIUserGroup
write-host '$WUIUserGroupPerm = '$WUIUserGroupPerm
write-host '$certname = '$certname
write-host '$certpath = '$certpath
write-host '$certpass = '$certpass


####################################
#INITIALIZING CONNECTION PARAMETERS# 
####################################
write-host -fore cyan "`nINITIALIZING CONNECTION PARAMETERS"

# Use preprovisioned credentials (if available) to login to LoadMaster
$Creds = $Null
$Creds = New-Object pscredential('bal', (ConvertTo-SecureString -String $oldLMpass -AsPlainText -Force))
$out = (Initialize-LmConnectionParameters -Address $loadbalancer -LBPort $LBPort -Credential $Creds).ReturnCode

# Prompt for credentials (if preprovisioned credentials are missing or are incorrect) to login to LoadMaster
if ($out -ne 200) {
do {
write-host -fore Green  "ENTER LOADMASTER ADMIN ACCOUNT AND PASSWORD VALID FOR ALL LOADMASTERS"
$Creds = $Null
$Creds = Get-Credential -message "ENTER LOADMASTER ADMIN ACCOUNT AND PASSWORD"
$out = (Initialize-LmConnectionParameters -Address $loadbalancer -LBPort $LBPort -Credential $Creds).ReturnCode
start-sleep -milliseconds 1000
}
while ($out -ne "200")
}
$msg = "$out - Initialize LM Connection Parameters with original bal password" ; write-host $msg 

# initialize connection to LoadMaster so further commands do not require common arguments
$out = (Initialize-LmConnectionParameters -Address $loadbalancer -LBPort $LBPort -Credential $Creds).returncode
$msg = "$out - Initialize LM Connection Parameters with original bal password"; write-host $msg

############################
#STARTING LICENSING PROCESS#
############################
$license = Get-LicenseInfo 
if($license.Data -eq $null) {
$msg = "STARTING LICENSING PROCESS. THIS CAN TAKE A FEW MINUTES" ; write-host -fore cyan $msg
$msg = "200 - Check to ensure LoadMaster is unlicensed"; write-host $msg
$eula = Read-LicenseEULA -LoadBalancer $loadbalancer -LBPort $LBPort -Credential $Creds   
$eula2 = Confirm-LicenseEULA  -Magic $eula.Data.Eula.MagicString
$out = (Confirm-LicenseEULA2 -Magic $eula2.Data.Eula2.MagicString -Accept yes).returncode
$msg = "$out - Process and accept EULA"; write-host $msg

if ($OrderID -ne "") {$out = (Request-LicenseOnline -KempId $KempID -Password $KempIDPass -OrderId $OrderId).returncode}
if ($OrderID -eq "") {$out = (Request-LicenseOnline -KempId $KempID -Password $KempIDPass).returncode}


$msg = "$out - Applying License to LoadMaster" ; write-host $msg
$out = (Set-LicenseInitialPassword -Passwd $newLMpass).returncode
$msg = "$out - Set new bal account password on LoadMaster" ; write-host $msg

}

########################################
# RE-INITIALIZING CONNECTION PARAMETERS#
########################################           
$password = ConvertTo-SecureString $newLMPass -AsPlainText -Force
$Creds = New-Object pscredential('bal', (ConvertTo-SecureString -String $NewLMpass -AsPlainText -Force))
$out = (Initialize-LmConnectionParameters -Address $loadbalancer -LBPort $LBPort -Credential $Creds).ReturnCode
$msg = "$out - Initialize LM Connection Parameters with new bal password" ; write-host $msg 


############################
# SETTING COMMON PARAMETERS#
############################
write-host -fore cyan "SETTING COMMON PARAMETERS"
        $LMParameters | ForEach-Object {
        sleep -Milliseconds 500
        $out = (Set-LmParameter @PSItem).ReturnCode
        $msg = "$out - Setting " ; write-host $msg @PSItem
        }
#end none ha parameter

#Set WUI port and WUI default management gateway
$out = (Set-SecAdminAccess -WuiNetworkInterfaceId 0 -WuiPort $LBPort -WuiDefaultGateway $dfltgw -Credential $Creds ).ReturnCode
$msg = "$out - Setting WUI port and WUI default management gateway" ; write-host $msg
sleep -Milliseconds 100

#Set WUI Cipherset and WUI TLS Protocols
$out = (Set-SecAdminWuiConfiguration -sessioncontrol $true -sessionbasicauth $false -sessionidletime $WUIidletime -Credential $Creds).ReturnCode
$msg = "$out - Setting WUI Cipherset and WUI TLS Protocols" ; write-host $msg
sleep -Milliseconds 200

#Setting of Ldap Endpoint for WUI authentication
if ($LdapEndpoint -ne $null){
$out = (New-LdapEndpoint -Name $LdapEndpoint -Server $LdapServer -LdapProtocol $LdapProtocol -AdminUser $LdapUser -AdminPass $LdapUserpass -Credential $Creds).ReturnCode
$msg = "$out - Creating LDAP Endpoint $LdapEndpoint" ; write-host $msg
sleep -Milliseconds 100

#Creating the LoadMaster admin usergroup
$out = (New-SecRemoteUserGroup -Group $WUIusergroup -Credential $Creds).ReturnCode
$msg = "$out - Creating local security group $WUIusergroup" ; write-host $msg

#Setting rights for LoadMaster admin usergroup
$out = (Set-SecRemoteUserGroup -Group $WUIusergroup -Permissions $WUIusergroupPerm -Credential $Creds).ReturnCode
$msg = "$out - Setting admin rights for $WUIusergroup to $WUIusergroupPerm" ; write-host $msg

#Setting Ldaps Endpoint, usergroup and domain for wui authentication
$out = (Set-SecWuiAuthentication -WuiLdapEp $LdapEndpoint -SessionAuthMode 23 -Wuiusergroups $WUIusergroup -WuiDomain $LdapEndpoint -Credential $Creds).ReturnCode
$msg = "$out - Enabling admin login using new LDAP Endpoint $LdapEndpoint" ; write-host $msg
}

#############################
#STARTING CERTIFICATE IMPORT#
#############################
write-host -fore cyan "STARTING CERTIFICATE IMPORT"  
if ($certname -ne $null){
#Import TLS certificate
$out = (New-TlsCertificate -Name $certname -Password $certpass -Path $certpath -Credential $Creds).ReturnCode
$msg = "$out - Importing certificate $certpath as $certname" ; write-host $msg
sleep -Milliseconds 100

#Import TLS certificate
$out = (New-TlsCertificate -Name $localcertname -Password $localcertpass -Path $localcertpath -Credential $Creds).ReturnCode
$msg = "$out - Importing certificate $localcertpath as $localcertname" ; write-host $msg
sleep -Milliseconds 100


#Assign TLS certificate to WUI Admin interface
$out = (Set-LmParameter -param admincert -value $certname -Credential $Creds).ReturnCode
$msg = "$out - Assigning WUI Admin certificate admincert = $certname" ; write-host $msg
sleep -Milliseconds 100
}

##########################################
#STARTING HIGH AVAILABILITY CONFIGURATION#
##########################################
if (($HAMode -eq "HA First") -or ($HAMode -eq "HA Second")) {$doHA = $True} Else {$doHA = $False}
if ($doHA) { Write-Host -fore cyan "STARTING HIGH AVAILABILITY CONFIGURATION" }
if ($doHA) {   
#Setting LoadMaster to HA Mode
$out = (Set-LmHAMode -HaMode $HaMode).ReturnCode
$msg = "$out - Setting LoadMaster to HA Mode = $HaMode" ; write-host $msg

#Setting LoadMaster CARP HA ID
$out = (Set-LmHAConfiguration -havhid $HAID).ReturnCode
$msg = "$out - Setting LoadMaster CARP HA ID to $HAID" ; write-host $msg

$out = (Set-NetworkInterface -InterfaceID 0 -shared $ShdETH[0] -partner $PaETH[0] -HACheck 1 -Credential $Creds).ReturnCode
$msg = "$out - Assigning eth0 partner IP and shared IP addresses" ; write-host $msg

#############################
#REBOOT FOR HA CONFIGURATION#
#############################
Write-Host -fore cyan "REBOOT FOR HA CONFIGURATION"  
$out = (Restart-Lm -Credential $Creds  -Force).ReturnCode
$msg = "$out - Reboot completed" ; write-host $msg
Sleep -seconds 10

# Set CARP to use broadcast
$out = (set-LmParameter -LoadBalancer $ShdETH[0] -LBPort $LBPort -Credential $creds  -Param macglobal -value "yes").returncode
$msg = "$out - Set HA to use multicast for CARP" ; write-host $msg

#Set local WUI admin certificate
$out = (Set-LmParameter -param localcert -value $localcertname -Credential $Creds).ReturnCode
$msg = "$out - Setting local WUI admin to $localcertname" ; write-host $msg

#Set admin WUI admin certificate
$out = (Set-LmParameter -param admincert -value $certname -Credential $Creds).ReturnCode
$msg = "$out - Setting admin WUI certificate to $certname" ; write-host $msg

}

##########################################
#STARTING NETWORK INTERFACE CONFIGURATION#
##########################################
write-host -fore cyan "STARTING NETWORK INTERFACE CONFIGURATION"
for ($i=1; $i -le $ETH.count; $i++) {
if ($ETH[$i] -ne $null) {
$out = (Set-NetworkInterface -InterfaceID  $i -IPAddress $ETH[$i] -Credential $Creds).ReturnCode
$msg = "$out - Assiging eth$i IP address" ; write-host $msg
if ($doHA){
$out = (Set-NetworkInterface -InterfaceID $i -shared $ShdETH[$i] -partner $PaETH[$i] -HACheck 1 -Credential $Creds).ReturnCode
$msg = "$out - Assigning eth$i partner IP and shared IP addresses" ; write-host $msg
}
}
}

##################################
#REBOOT FOR NETWORK CONFIGURATION#
##################################
#if ($doHA){ 
#Write-Host -fore cyan "REBOOT FOR NETWORK CONFIGURATION"  
#$out = (Restart-Lm -Credential $Creds  -Force).ReturnCode
#$msg = "$out - Reboot completed" ; write-host $msg
#Sleep -seconds 10

#######################
# Assign WUA localcert#
#######################
# $out = (Set-LmParameter -param localcert -value $certname -Credential $Creds).ReturnCode
# $msg = "$out - Setting local WUI admin cert to $certname" ; write-host $msg
}

###############################################
#REBOOT TO ENSURE ALL PARAMETERS ARE IN EFFECT#
###############################################
#Write-Host -fore cyan "REBOOT TO ENSURE ALL PARAMETERS ARE IN EFFECT"  
#$out = (Restart-Lm -Credential $Creds  -Force).ReturnCode
#$msg = "$out - Reboot completed" ; write-host $msg
Write-Host -fore cyan "`nCOMPLETED LICENSING AND SETUP FOR LoadMaster $Hostname`n" 

}

#if ($doHA) {
#$out = (set-LmParameter -LoadBalancer $ShdETH[0] -LBPort $LBPort -Credential $creds  -Param macglobal -value "yes").returncode
#$msg = "$out - Set HA to use multicast for CARP" ; write-host $msg
#}

<#Used Parameter Information



Set-LmParameter
A large number of LoadMaster parameters can be configured using the Set-LmParameter command.

localcert This parameter is only relevant when using HA.

admincert The certificate used, if any, for the administrative interface.

admingw When administering the LoadMaster from a non-default interface, this option allows the user to specify a different defaultgateway for administrative traffic only.


sshaccess
Specify over which addresses remote administrative SSH access to the LoadMaster is allowed.


sshport
Specify the port used to access the LoadMaster via the SSH protocol.


wuiaccess
Enables or disables access to the Web User Interface (WUI).

enableapi Enables the programmable command API Interface. Note: If this is disabled, the API will no longer be accessible.

sessionauthmode
Specifies the authentication mode for the LoadMaster. Refer to the following table for values:

| RADIUS | LDAP | Local Value | Authent. Author. | Authent. | Authent. Author.
7 | No No | No | No No
263 | Yes No | No | Yes Yes
775 | Yes Yes | No | Yes Yes
23 | No No | Yes | Yes Yes
22 | No No | Yes | No Yes
788 | Yes Yes | Yes | No No
790 | Yes Yes | Yes | No Yes
791 | Yes Yes | Yes | Yes Yes
789 | Yes Yes | Yes | Yes No
773 | Yes Yes | No | Yes No
262 | Yes No | No | No Yes
774 | Yes Yes | No | No Yes
772 | Yes Yes | No | No No
278 | Yes No | Yes | No No
279 | Yes No | Yes | Yes Yes

ldapserver Specifies the LDAP server to use for authentication.

wuidomain Specify the domain to use if no domain is provided in the username when group WUI authentication is in use. It is always used as the domain for group search if the Windows logon is used in the format prefix\username.

sessionidletime Specifies the number of seconds that the WUI can be idle before logging the user out. This can be set from 60 to 86400 seconds.

DNSNamesEnable
When this option is enabled, the LoadMaster automatically attempts to update any changed DNS names (based on the update
interval):
- If the address is not found, or if it is the same as before – nothing is done (except a log entry is generated).
- If the address is different, the Real Server entry is updated with the new address, if possible.
- If the new address is invalid for some reason, for example if it is a non-local address and the nonlocalrs option is
disabled, no changes are made and a log is generated.

nameserver The DNS server the LoadMaster will use for name resolution. Setting this parameter to an empty string will delete the name servers. The last remaining name server cannot be deleted if the dnssecclient parameter is enabled.

hostname The hostname assigned to the LoadMaster.

searchlist The domain suffix search list when performing DNS resolution.

Before setting the default gateway, the network interface addresses must be configured, for example:
Set-NetworkInterface -GWIface 1

Dfltgw Specify the IPv4 default gateway that is to be used for communicating with the internet.

dfltgwv6 Specify the IPv6 default gateway that is to be used for communicating with the internet.


ntphost Specifies the time synchronization server. Multiple hosts can be specified using a space-separated list.

timezone Specifies the time zone of the LoadMaster.

#>


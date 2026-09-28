$ScriptVersion = "7.2.54.3"
Clear-Host
$catch = start-sleep -milliseconds 1500
$PS_Required = "7.2.53.0"                                  ## This is the required minimum release of LoadMaster PowerShell Module for this script to function
$LM_Required = "7.2.53.0"                                  ## This is the required minimum release of LoadMaster Operating System for this script to function

#Fixes 
# - LAST UPDATE: 2/1/2022
# - Fix HTML5 with ESP rules ordering 
# - Added SubVS for new ESP auth mode
# - Removed install of intermediate and root certificates
# - Added check to ensure correct version of Kemp Powershell module and LoadMaster OS is installed
# - Added SAML configuration option
# - Enhanced user feedback as script is running
# - SAML sanity checks added for Token Signing Cert and Metadata file
# - Added support for using a list of hostnames is the vdiservers.txt file
# - Removed checking for format of data in vdiservers.txt and storefront.txt files
# - Added option to set SSL Reencryption on virtual services
# - Added option to set default gateway on virtual services


#REQUIREMENTS 
# 1. Text file called “vdiservers.txt.” containing all your VDI Server IP addresses.
# 2. Text file called “storefront.txt.” containing all your StoreFront Servers IP addresse
# 3. Certificate file in pem or pfx format for virtual service
# 4. If using LDAP or Radius, availability of a LDAP or Radius authentication service
# 5. If using SAML Authentiation,availablity of Token Signing Cert & IDP Metadata.xml file
# 5. Citrix StoreFront Fully Qualified Domain Name, e.g. citrix.kemptest.com
# 6. Citrix StoreFront URL, e.g. /Citrix/KempWeb
# 7. IP address to assign to Citrix Virtual Service
# 8. CONFIGURED AND LICENSED KEMP LOADMASTER (LMOS 7.2.53 or newer) 
# 9. LOADMASTER DNS RESOLVER POINTING TO DNS SERVER THAT CAN RESOLVE hostnames (if used for input files)



#####################################################
#Check for Kemp Powershell Build minimum requirements
#####################################################
$PS_R3 = ($PS_Required.Split("."))[2]

####################################################
# Ensure correct Kemp PowerShell module is installed 
####################################################

if ((Test-Path "C:\Program Files\WindowsPowerShell\Modules\KEMP.LoadBalancer.Powershell") -or (Test-Path "C:\Program Files (x86)\WindowsPowerShell\Modules\KEMP.LoadBalancer.Powershell")) {
    $catch = Remove-Module -Name KEMP.LoadBalancer.Powershell -errorAction SilentlyContinue
    $catch = Start-Sleep -Seconds 1
    $catch = Import-Module -Name KEMP.LoadBalancer.Powershell -MinimumVersion $PS_Required -ErrorAction SilentlyContinue
    }

$PS_Version = $Null
$PS_Version = (Get-Module -name KEMP.LoadBalancer.Powershell).Version
if ($PS_Version -eq $Null) {
    write-host -fore red "SCRIPT TERMINATING - Kemp PowerShell Module not installed. Please install version $PS_Required or newer and rerun script"
    Read-Host -prompt "Press Enter to terminate script"
    exit
    }

$PS_V3 = ($PS_Version.Build)

if ($PS_V3 -lt $PS_R3) {
    write-host -fore Red "SCRIPT TERMINATING - Newer Kemp PowerShell module required. Please install version $PS_Required or newer and rerun script"
    read-host -Prompt "Press Enter to terminate script"
    exit
    }


#################
# Create Log File                                  ## DO NOT UPDATE THIS SECTION
#################
$dd = Get-Date -Format yyMMddhhmmss                ## Get a date time indel to prepend to file name
$logfile = "Citrix_Script_Log_"+$dd+".log"         ## Create a unique log file name including datetime 
add-content -path $logfile -Value "Log file for Citrix Script`nVersion Number = $ScriptVersion"


#########################################################################################################################
#                                               START CONFIGURING VARIABLES
#########################################################################################################################


#############################
# Wait timer between commands 
#############################
$wait = 500                                      ## UPDATE - Set wait state between commands (increase if script generates errors when running) 


#######################
# Script home directory
#######################
$scripthome = "C:\ScriptHome"                    ## UPDATE - Location to hold files and run powershell commands from
set-location -path $scripthome


#####################
# LoadMaster settings
#####################
$LoadmasterIP = "192.168.0.28"                   ## UPDATE - LoadMaster Management IP Address (shared address if HA)
$LoadMasterPort = "443"                          ## UPDATE - Update only if using a nonstandard management port
$Search_Domain = "kemptech.biz"                  ## UPDATE - Value is critical when input files use hostnames instead of IP addresses
$CipherSet = "FIPS"                              ## UPDATE - Recommend FIPS or Bestpractices (select from standad cipher sets on Loadmaster)

#################################
# Citrix Virtual Service settings 
#################################
$SF_File = "storefront.txt"                      ## UPPATE - File Name for file containing storefront IP addresses
$VDI_File = "vdiservers.txt"                     ## UPPATE - File Name for file containing VDI server IP addresses
$VirtualServiceIp = "192.168.0.100"              ## UPDATE - Virtual Service IP (used to publish Citrix StoreFront service)                      
$Use_HTML5 = $True                               ## UPDATE - If set to $True then build HTML5 listeners, if $False use only ICA listeners (Must be $True or $False)
$Reencrypt = $True                               # work in progress - feature not currently enabled.           ## UPDATE - If the Cirtix HTML5 service is configured for TLS, set to $True else set to $False
$Def_GW = "192.168.0.2"                          ## UPDATE - Used to set the Default Gateway for the listener virtual services

#################
#Citrix StoreName
#################
$StorePath = "/Citrix/kempWeb"                   ## UPDATE - Citrix Store Name URL
$FQDN = "citrix.kemptech.biz"                    ## UPDATE - Citrix External FQDN


####################
# Import Certificate 
####################
$doCert = $True                                  ## UPDATE - Set to $True to load StoreFront TLS certificate on LoadMaster (used for creation of virtual service)
$CertFile = "CitrixCert.pfx"                     ## UPDATE - Filename of StoreFront TLS Certficate (place cert in C:\ScriptHome)
$CertName = "CitrixCert"                         ## UPDATE - Name of StoreFront TLS Certificate to be loaded to LoadMaster
                                                 ## Ensure that SSL cert contains full chain, otherwise import intermediate or Root certs 

#######################
# Authentication Method                         # NOTE - Only one option can be set to $True or all options can be set to $False
####################### 
$Use_LDAP = $True							    ## UPDATE - If set to $True, then use LDAP for user auth to StoreFront (Must be $True or $False)
$Use_Radius = $False                            ## UPDATE - If set to $True, then use Radius for user auth to StoreFront (Must be $True or $False)
$Use_SAML = $False                              ## UPDATE - If set to $True, then use SAML for user auth to StoreFront (Must be $True or $False)
                                               

##########################################################################
# Client Side LDAP or Radius ESP SSO settings. Ignore if SAML is required. 
##########################################################################
$AuthServers = "192.168.0.10"               ## UPDATE - Modify if $Use_LDAP or $Use_Radius is $True. (One or more IP addresses, space seperated)
$TestAccou = "ldapuser@kemptech.biz"        ## UPDATE - Modify if $Use_LDAP or $Use_Radius is $True. (Account used to bind to LDAP or healthcheck LDAP or Radius)
$Domain ="kemptech.biz" 		            ## UPDATE - Modify if $Use_LDAP or $Use_Radius is $True. (LDAP or Radius SSO Domain)


###################################################################
# Client Side SAML ESP SSO settings. Ignore if using LDAP or Radius
###################################################################
$SAMLSPEntityID = "LoadMasterSAML"             ## UPDATE - Entity ID used to identify your Citrix SAML App
$SAMLmetadata =   "FederationMetadata.xml"     ## UPDATE - Name of Metadata file downlaoded from IDP Portal
$Domain = "kemptech.biz"                       ## UPDATE - Name of new SAML Configuration
$SAMLIDPCert = "Azure-Citrix.crt"              ## UPDATE - Name of SAML IDP Cerificate file. Must be located in current working directory
$SAMLIDPCertName ="SAML-Citrix"                ## UPDATE - Name of SAML Token signing certificate
#$SAMLIDPCertName = "SAML-Azure-Citrix"


#########################################################################################################################
#                                               END CONFIGURE VARIABLES
#########################################################################################################################

#########################################################################################################################
#########################################################################################################################
##                                           DO NOT MODIFY SETTINGS BELOW THIS LINE
#########################################################################################################################
#########################################################################################################################

#########################################################################################################################
#                                               START STANDARD VARIABLES
#########################################################################################################################

#####################################
# Standard Settings - Virtual Service 
#####################################
$VSName = "Citrix StoreFront Gateway"              ## Standard value used in script and template
$VSPort = "443"                                    ## Standard value used in script and template
$RSPort = "443"                                    ## Standard value used in script and template

##################################
# Standard Settings - VDI Services 
##################################
$starting_index = 1                                ## Standard value used in script and template
$starting_port = 4431                              ## Standard value used in script and template

######################################
# Standard Settings - VDI 2598 Service 
######################################
$vdi2589_vs_name ="Citrix_Workspace_VDI"           ## Standard value used in script and template
$vdi2589_RS_Port ="443"                           ## Standard value used in script and template

#######################################
# Standard Settings - VDI HTML5 Service
#######################################
$vdi8008_vs_name ="Citrix_HTML5_VDI"               ## Standard value used in script and template
$vdi8008_RS_Port ="443"                           ## Standard value used in script and template

#########################################################################################################################
#                                               END STANDARD VARIABLES
#########################################################################################################################

######################################################################
# Provide info on script and an option to continue or terminate script
######################################################################

Write-Host -fore Cyan "SCRIPT TO INSTALL CITRIX STOREFRONT"
write-host "`nThis script runs from the folder $scripthome. `n`nThis folder must contain the following files:"
Write-Host "  - $scripthome\$SF_File containing all StoreFront Server IP addresses."
Write-Host "  - $scripthome\$VDI_File containing all VDI Server IP addresses."
write-host "  - $scripthome\$CertFile for StoreFront TLS Certficate"
if ($Use_SAML) { write-host "  - $scripthome\$SAMLIDPCert for SAML IDP Certificate" }
write-host "To run this script, you will need the admin account and password for the LoadMaster."
write-host -fore green  "ENTER (Y) TO CONTINUE, ANY OTHER VALUE TO TERMINATE" -NoNewline ; $YN = read-host " "
if (-NOT ($YN -match "^Y")) {exit}

###############################
# Run sanity check on variables
###############################

# CHECKING ESP RELATED VARIABLES
if (-not (($Use_Radius.gettype().name -eq "Boolean") -AND ($Use_LDAP.gettype().name -eq "Boolean") -AND ($Use_SAML.gettype().name -eq "Boolean"))) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - USE_RADIUS OR USE_LDAP OR USE_SAML SETTINGS INCORRECT"
    Write-Host -fore red ''
    Write-Host -fore red '????????????????????????????????????????????????????????????????????????????????????????'
    Write-Host -fore red '? $Use_Radius, $Use_LDAP and $Use_SAML must be boolean values set to $True or $False.  ?'
    Write-Host -fore red '? Please adjust valuses to either $True or $False for these variables                  ?'
    Write-Host -fore red '? Script is terminating.                                                               ?'
    Write-Host -fore red '????????????????????????????????????????????????????????????????????????????????????????'
    Write-Host -fore red ''
    Read-Host -prompt "Press Enter to terminate script"
    exit 
    }
$x = 0
if ($Use_Radius) { $x = $x + 1 }
if ($Use_LDAP)   { $x = $x + 1 }
if ($Use_SAML)   { $x = $x + 1 }
if ($x -eq 0) {
    add-content -path $logfile -Value " Running script without ESP options"
    Write-Host -fore cyan "`nBUILDING CITRIX VIRTUAL SERVICES WITHOUT KEMP EDGE SECURITY PACK"
    $catch = start-sleep -milliseconds 1500
    $Use_ESP = $False
    }
if ($x -ge 2) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - USE_RADIUS OR USE_LDAP OR USE_SAML SETTINGS INCORRECT"
    Write-Host -fore red ''
    Write-Host -fore red '?????????????????????????????????????????????????????????????????????????????????????????'
    Write-Host -fore red '? Only one ESP method is allowed. Configuration currently shows more than one set True. ?'
    Write-Host -fore red '? Please adjust settings for $Use_Radius, $Use_LDAP or $Use_SAML and rerun script       ?'
    Write-Host -fore red '? Script is terminating.                                                                ?'
    Write-Host -fore red '?????????????????????????????????????????????????????????????????????????????????????????'
    Write-Host -fore red ''
    Read-Host -prompt "Press Enter to terminate script"
    exit 
    }
if ($x = 1) {
    add-content -path $logfile -Value " Running script with ESP options"
    $catch = start-sleep -milliseconds 1500
    $Use_ESP = $True
    }

########################################################################
# Check that vdiservers.txt, storefront.txt and SAML Config Files exist. 
########################################################################

# Checking for required files
if ( -NOT ((Test-Path ".\$VDI_File") -AND (Test-Path ".\$SF_File"))) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - vdiservers.txt or storefront.txt file missing"
    Write-Host -fore red ""
    Write-Host -fore red "???????????????????????????????????????????????????????????????????????????????????????????????????"
    Write-Host -fore red "? Either vdiservers.txt or storefront.txt is not present in the directory the script is being ran ?"
    Write-Host -fore red "? Change directory to the location holding vdiservers.txt and storefront.txt                      ?"
    Write-Host -fore red "? Or move/create these files in the current directory                                             ?"
    Write-Host -fore red "? Please rerun script once above prerequisites are met.                                           ?"
    Write-Host -fore red "? Script is terminating.                                                                          ?"
    Write-Host -fore red "???????????????????????????????????????????????????????????????????????????????????????????????????"
    Write-Host -fore red ""
    Read-Host -prompt "Press Enter to terminate script"
    exit 
    }

if ($Use_SAML -and (-not (Test-Path .\$SAMLIDPCert))) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - $Scripthome\$SAMLIDPCert file missing"
    Write-Host -fore red ""
    Write-Host -fore red "???????????????????????????????????????????????????????????????????????????????????????????????????"
    Write-Host -fore red "? Missing SAML IPP Cert File. This certificate file (.cer or .crt) must be in the working directory"
    Write-Host -fore red "? Please place file $SAMLIDPCert in directory $ScriptHome"
    Write-Host -fore red "? Please rerun script once above prerequisites are met."
    Write-Host -fore red "? Script is terminating."
    Write-Host -fore red "???????????????????????????????????????????????????????????????????????????????????????????????????"
    Write-Host -fore red ""
    Read-Host -prompt "Press Enter to terminate script"
    exit 
    }


############################################
# Check for access to LoadMaster IP address
############################################
$ok = ((New-Object System.Net.Sockets.TcpClient).BeginConnect("$LoadMasterIP", "$LoadMasterPort", $Null, $Null)).AsyncWaitHandle.WaitOne("2000", $Null)

if ($ok) {
    add-content -path $logfile -Value "  Connection to LoadMaster IP address $LoadmasterIP successful"
    Write-Host -fore cyan "CONNECTION TO LOADMASTER IP ADDRESS $LoadmasterIP SUCCESSFUL"
    }
else { 
    add-content -path $logfile -Value "TERMINATING SCRIPT - LoadMaster IP address $LoadmasterIP is NOT reachable over the network"
    Write-Host -fore Red "Script Terminating. LoadMaster IP address $LoadmasterIP is NOT reachable over the network" 
    Read-Host -prompt "Press Enter to terminate script"
    exit
    }
 
################################################
# LOGIN to LoadMaster and enable API interface #
################################################

$eapi = $False
do {
    start-sleep -Seconds 1
    Write-Host -fore green "`nENTER LOADMASTER ADMIN ACCOUNT NAME AND PASSWORD"
    $KempCreds = Get-Credential -message "ENTER LOADMASTER ADMIN ACCOUNT NAME AND PASSWORD"
    $Login = Initialize-LmConnectionParameters -Address $LoadmasterIP -LBPort $LoadMasterPort -Credential $KempCreds
    $eapi = Enable-SecAPIAccess -LoadBalancer $LoadmasterIP -Credential $KempCreds
    }
while ($eapi.ReturnCode -ne "200")

if ($eapi.ReturnCode -eq "200") {
    add-content -path $logfile -Value "Login Request to LoadMaster $LoadMasterIP Successful"
    write-host "200 - Login Request to LoadMaster $LoadMasterIP Successful"
    }

#######################################################
# Check for minimum LoadMaster Operating System version
#######################################################
$LM_R = ($LM_Required.Split("."))[2]
$LM_V = ((get-lmallparameters -Loadbalancer $LoadmasterIP -Credential $KempCreds).data.AllParameters.version).Split(".")[2]
if ($LM_V -ge $LM_R) { 
    add-content -path $logfile -Value "  - Verified LMOS version is equal to our newer than $LM_Required"
    write-host "200 - Verified LMOS version is equal to our newer than $LM_Required"
    }
else {
    add-content -path $logfile -Value "  - Failed LMOS version check. LMOS is older than $LM_Required"
    write-host -fore red "`nTERMINATING SCRIPT - Please patch LoadMaster to a minimum of version $LM_Required and rerun script"
    Read-Host -prompt "Press Enter to terminate script"
    exit
    }


##############################################################################
# Check for existing Citrix virtual services and if present - TERMINATE SCRIPT
##############################################################################
$rc = (Get-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $starting_port -VSProtocol tcp).ReturnCode
if ($rc -eq 200) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - Existing Citrix virtual service found." 
    Write-Host -fore red "`nTERMINATING SCRIPT - LoadMaster has already been configured for Citrix StoreFront"
    Read-Host -prompt "Press Enter to terminate script"
    exit
    }


###################################################################################################
# Check LoadMaster to see if it includes ESP license - if no - set Use_LDAP and Use_Radius to False
###################################################################################################
$License_ESP = (Get-LicenseInfo -Loadbalancer $LoadmasterIP -Credential $KempCreds).data.LicenseInfo.ESP

if (($License_ESP -ne "yes") -and ($Use_ESP) ) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - ESP is required and LoadMaster is not licensed for ESP"
    write-host -fore DarkYellow "TERMINATING SCRIPT - ESP is required and LoadMaster is not licensed for ESP"
    read-host "`nPress enter to terminate script"
    exit
    }

if ($License_ESP -eq "yes") {
    add-content -path $logfile -Value "  - ESP License was found - Honoring settings for Use_LDAP, Use_Radius and Use_SAML"
    Write-host "200 - ESP License was found - Honoring settings for Use_LDAP, Use_Radius and Use_SAML"
    }

$catch = start-sleep -milliseconds $wait

###########################################################
# Check to see if certificate files are available if needed
###########################################################
$isCert = (Test-Path $certfile)
$isSam = (Test-Path $SAMLIDPCert)
$isSamFile = (Test-Path $SAMLmetadata)

################################################
# Check to see if certificates already installed
################################################
$doCert = ((get-TLSCertificate -Loadbalancer $LoadmasterIP -Credential $KempCreds -CertName $CertName).ReturnCode -ne "200")
$doSAML = ((get-TLSCertificate -Loadbalancer $LoadmasterIP -Credential $KempCreds -CertName $SAMLIDPCertName).ReturnCode -ne "200")

if ( $doCert -AND (-Not $isCert)) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - missing certificate file - $scripthome\$certfile"
    Write-Host -fore red "SCRIPT TERMINATING - certificate file named  $scripthome\$certfile missing."
    Write-Host -fore red "Please add file to $scripthome and rerun script."
    Read-Host -prompt "Press Enter to terminate script"
    exit 
    }

if ( $doSAML -AND (-Not $isSam)) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - missing certificate file - $scripthome\$SAMLIDPCert"
    Write-Host -fore red "SCRIPT TERMINATING - certificate file named  $scripthome\$SAMLIDPCert missing."
    Write-Host -fore red "Please add file to $scripthome and rerun script."
    Read-Host -prompt "Press Enter to terminate script"
    exit 
    }

if ( $doSAML -AND (-Not $isSamFile )) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - missing SAML metadata file - $scripthome\$SAMLmetadata"
    Write-Host -fore red "SCRIPT TERMINATING - SAML metadata file  $scripthome\$SAMLmetadata missing."
    Write-Host -fore red "Please add file to $scripthome and rerun script."
    Read-Host -prompt "Press Enter to terminate script"
    exit 
    }

##############################################################################
# Read file and extract individual lines that are in IP address or FQDN format
##############################################################################
# $SF_asIP = $False
# $VDI_asIP = $False
$servers = $null
$servers = New-Object System.Collections.Generic.List[System.Object]
$StoreFrontIP = $null
$StoreFrontIP = New-Object System.Collections.Generic.List[System.Object]

##############################################################
# Loading StoreFront Info from File (Skip blank lines in file)
##############################################################
$StoreFrontIP = @(Get-Content -Path ".\$SF_File" | Where-Object { $_.Trim() -ne '' })

##############################################################
# Loading VDI Server Info from File (Skip blank lines in file)
##############################################################
$servers = @(Get-Content -Path ".\$VDI_File" | Where-Object { $_.Trim() -ne '' })

################################################################################################
# Sanity Check - if no VDI Servers or StoreFront Servers extracted from files - terminate script
#################################################################################################
if ($storefrontip.count -eq 0) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - No StoreFront Servers Identified."
    Write-Host -fore red "`nERROR - SCRIPT TERMINATING - No StoreFront Servers Identified." 
    Read-Host -prompt "Press Enter to terminate script" 
    exit 
    }
if ($servers.count -eq 0) {
    add-content -path $logfile -Value "TERMINATING SCRIPT - No VDI Servers Identified."
    Write-Host -fore red "`nERROR - SCRIPT TERMINATING - No VDI Servers Identified."
    Read-Host -prompt "Press Enter to terminate script"
    exit
    }
Write-Host -fore Cyan "`nLIST OF STOREFRONT SERVERS:"
$StoreFrontIP
Write-Host -fore Cyan "`nLIST OF VDI SERVERS:"
$servers

##########################
# All VARIABLES CONFIGURED
########################## 
Write-Host -fore Cyan "`nCOMPLETED SANITY CHECK ON VARIABLES AND FILES"

######################################################
# Load Log File with Variables and Standard Parameters
######################################################
add-content -path $logfile -Value "`nLIST OF VARIABLES AND VALUES"
add-content -path $logfile -Value "----------------------------"
add-content -path $logfile -Value "wait = $wait"
add-content -path $logfile -Value "LoadmasterIP = $LoadmasterIP"
add-content -path $logfile -Value "LoadMasterPort = $LoadMasterPort"
add-content -path $logfile -Value "VirtualServiceIp = $VirtualServiceIp"
add-content -path $logfile -Value "Use_HTML5 = $Use_HTML5"
add-content -path $logfile -Value "`n#### RADIUS AND LDAP SETTINGS ####"
add-content -path $logfile -Value "Use_Ldap = $Use_Ldap"
add-content -path $logfile -Value "Use_Radius = $Use_Radius"
add-content -path $logfile -Value "AuthServers = $AuthServers"
add-content -path $logfile -Value "AuthUser = $ServiceAccount"
add-content -path $logfile -Value "AuthPass = #####"
add-content -path $logfile -Value "Domain = $Domain"
add-content -path $logfile -Value "SharedSecret = #####"
add-content -path $logfile -Value "`n#### CITRIX STOREFRONT SETTINGS ####"
add-content -path $logfile -Value "StorePath = $StorePath"
add-content -path $logfile -Value "FQDN = $FQDN"
add-content -path $logfile -Value "CertName = $CertName"
add-content -path $logfile -Value "CertFile = $CertFile"
add-content -path $logfile -Value "CertPass = #####"
add-content -path $logfile -Value "CA_Name = $CA_Name"
add-content -path $logfile -Value "CA_File = $CA_File"
add-content -path $logfile -Value "`n#### STOREFRONT SERVER LIST ####"
add-content -path $logfile -Value "RA_Name = $RA_Name"
add-content -path $logfile -Value "RA_File = $RA_File"
add-content -path $logfile -Value $StoreFrontIp
add-content -path $logfile -Value "`n#### VDI SERVER LIST ####"
add-content -path $logfile -Value $servers
add-content -path $logfile -Value "`n#### STANDARD VIRTUAL SERVICE PARAMETERS####"
add-content -path $logfile -Value "VirtualServiceName = $VSName"
add-content -path $logfile -Value "VirtualServicePort = $VSPort"
add-content -path $logfile -Value "RealServerPort = $RSPort"
add-content -path $logfile -Value "`n#### COMMON VDI PARAMETERS ####"
add-content -path $logfile -Value "starting_index = $starting_index"
add-content -path $logfile -Value "starting_port = $starting_port"
add-content -path $logfile -Value "`n#### STANDARD VDI 2598 PARAMETERS ####"
add-content -path $logfile -Value "vdi2589_vs_name = $vdi2589_vs_name"
add-content -path $logfile -Value "vdi2589_RS_Port = $vdi2589_RS_Port"
add-content -path $logfile -Value "`n#### Standard VDI HTML5 VS Parameters"
add-content -path $logfile -Value "vdi8008_vs_name = $vdi8008_vs_name"
add-content -path $logfile -Value "vdi8008_RS_Port = $vdi8008_RS_Port"
add-content -path $logfile -Value "############# END OF PARAMETERS ###########"


#################################
# Install StoreFront Certificates
#################################
# Install TLS Certificate for use by Virtual Services
if ($doCert) {
    do {
        $null = start-sleep -Seconds 1
        Write-Host -fore green "`nENTER PASSWORD TO INSTALL CERTIFICATE - $CertFile"
        $password = Read-Host "Enter password for StoreFront Virtual Service TLS Certificate - $CertFile" -AsSecureString
        $password = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
        $CertPass = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($password)
        $catch = (New-TlsCertificate -Loadbalancer $LoadmasterIP -Credential $KempCreds -Name $CertName -Password $CertPass -Path $CertFile).ReturnCode
        Write-Host "$catch - Installing TLS certificate from $certfile"
        add-content -path $logfile -Value "$catch - Installing TLS certificate from $certfile"
        }
    while ($catch -ne 200)
    }
$catch = start-sleep -milliseconds $wait
$catch = start-sleep -milliseconds $wait
$CertPass = $Null

# Install Intermediate Certificate to validate SAML IDP certificates
if ($Use_SAML -and $doSAML) {
    $catch = (New-TlsIntermediateCertificate -Loadbalancer $LoadmasterIP -Credential $KempCreds -Name $SAMLIDPCertName -Path $SAMLIDPCert).ReturnCode
    Write-Host "$catch - Importing SAML Token Signing Certificate"
    add-content -path $logfile -Value "$catch - Importing SAML Token Signing Certificate"
    }

############################
# Global LoadMaster Settings                                                          
############################
write-host -fore cyan "`nSETTING COMMON LOADMASTER PARAMETERS"
add-content -path $logfile -Value "SETTING COMMON LOADMASTER PARAMETERS"

# SETTING OUTBOUND CIPHER  (Recommend FIPS or BestPractices)
$Catch = (Set-LmParameter -LoadBalancer $LoadmasterIP -Credential $KempCreds  -Param OutboundCipherset -Value "$CipherSet").ReturnCode
write-host "$catch - Setting OutboundCipherset = $CipherSet"
add-content -path $logfile -Value "$catch - Setting OutboundCipherset = $CipherSet"
start-sleep -Milliseconds $wait

# SETTING INBOUND CIPHER (Recommend FIPS or BestPractices)
$Catch = (Set-LmParameter -LoadBalancer $LoadmasterIP -Credential $KempCreds  -Param WUICipherset -Value "$CipherSet").ReturnCode
write-host "$catch - Setting WUICipherset = $CipherSet"
add-content -path $logfile -Value "$catch - Setting WUICipherset = $CipherSet"
start-sleep -Milliseconds $wait

# Share SubVS Persistence
$catch = ( Set-LmParameter -Loadbalancer $LoadmasterIP -Credential $KempCreds -Param ShareSubVSPersist -Value 1 ).ReturnCode
Write-Host "$catch - Setting Global LoadMaster Parameters"
add-content -path $logfile -Value "$catch - Enable Share SubVS Persistence"
start-sleep -Milliseconds $wait

# Explicitly set management gateway to default GW
$GW = (Get-LmParameter -Loadbalancer $LoadmasterIP -Credential $KempCreds -Param dfltgw).data.dfltgw
$Catch =  (Set-LmParameter -Loadbalancer $LoadmasterIP -Credential $KempCreds -Param admingw -Value "$GW").ReturnCode
Write-Host "$catch - Setting Management Default Gateway to $GW"
add-content -path $logfile -Value "$catch - Setting Management Default Gateway to $GW"
start-sleep -Milliseconds $wait

# Disable SSL Renegotiation
$catch = (Set-LmParameter -Loadbalancer $LoadmasterIP -Credential $KempCreds -param sslrenegotiate -value 0).ReturnCode
write-host "$catch - Disable SSL Renegotiation"
add-content -Path $logfile -value "$catch - Disable SSL Renegotiation"
start-sleep -Milliseconds $wait

# Enable Subnet Originating Request (SOR) appliance wide 
$catch = (Set-LmParameter -Loadbalancer $LoadmasterIP -Credential $KempCreds -Param subnetorigin -Value 1).ReturnCode                
write-host "$catch - Enable subnet originating request based NAT"
add-content -path $logfile -Value "$Catch - Enable subnet originating request based NAT"
start-sleep -Milliseconds $wait

# Allows loadbalancing of servers located on a different subnet from the load balancer
$catch = (Set-LmParameter -Loadbalancer $LoadmasterIP -Credential $KempCreds -Param nonlocalrs -Value 1).ReturnCode            
write-host "$catch - Enable load balancing of non-local real servers"
add-content -path $logfile -Value "$catch - Enable load balancing of non-local real servers"
start-sleep -Milliseconds $wait

# Restict Wed User Interface to TLS1.2 and TLS1.3
$catch = (Set-LmParameter -Loadbalancer $LoadmasterIP -Credential $KempCreds -Param WUITLSProtocols -Value 7).ReturnCode
write-host "$catch - Restict Web User Interface to TLS1.2 and TLS1.3"
add-content -path $logfile -Value "$catch - Restict Web User Interface to TLS1.2 and TLS1.3"
start-sleep -Milliseconds $wait

# Enable Movement of Default Gateway
$Catch = (Set-LmParameter -LoadBalancer $LoadmasterIP -Credential $KempCreds -param multigw -value 1).ReturnCode
write-host "$catch - Enable Movement of Default Gateway"
add-content -Path $logfile -value "$catch - Enable Movement of Default Gateway"
start-sleep -Milliseconds $wait

# Force use of per virtual service default gateway
$Catch = (Set-NetworkConfiguration -LoadBalancer $LoadmasterIP -Credential $KempCreds -OnlyDefaultRoutes 1).ReturnCode
write-host "$catch - Set Virtual Services to only use gateway defined in virtual service"
add-content -Path $logfile -value "$catch - Set Virtual Services to only use gateway defined in virtual service"
start-sleep -Milliseconds $wait

# Set DNS Search Path
$Catch = (Set-NetworkDNSConfiguration -LoadBalancer $LoadmasterIP -Credential $KempCreds -Searchlist "$Search_Domain").ReturnCode
write-host "$catch - Set Loadmaster DNS client search domain to $Search_Domain"
add-content -Path $logfile -value "$catch - Set Loadmaster DNS client search domain to $Search_Domain"
start-sleep -Milliseconds $wait


################################
#Create Radius MFA Configuration 
################################
if ($Use_Radius) {
    add-content -path $logfile -Value "`n#### Radius MFA Configuration ####"
    Write-Host -fore cyan "`nCREATING NEW RADIUS CONFIGURATION"
    Write-Host -fore Green "ENTER PASSWORD FOR RADIUS SERVER TEST ACCOUNT"
    $TestAccountPass = Read-Host -Prompt  'Please Enter Password for Radius Auth Server Test Account' -AsSecureString  ## UPDATE - Modify if $Use_LDAP or $Use_Radius is $True. (Password for $ServiceAccount)
    Write-Host -fore Green "ENTER RADIUS SERVER SHARED SECRET"
    $RadiusSharedSecret = Read-Host -Prompt  'Enter Radius Shared Secret' -AsSecureString ## UPDATE - Modify if $Use_LDAP or $Use_Radius is $True. (Radius shared secret)

    $catch = (New-SSODomain -Loadbalancer $LoadmasterIP -Credential $KempCreds -Domain $Domain).ReturnCode
    Write-Host "$catch - Creating new RADIUS client side SSO domain"
    add-content -path $logfile -Value "$catch - Creating new RADIUS client side SSO domain"
    $catch = (Set-SSODomain -Loadbalancer $LoadmasterIP -Credential $KempCreds -Domain $Domain -logon_domain $Domain -auth_type RADIUS -Server $AuthServers -radius_shared_secret $RadiusSharedSecret -logon_fmt Principalname -sess_tout_idle_pub 1800 -sess_tout_idle_priv 1800 -testuser $TestAccount -testpass $TestAccountPass).ReturnCode
    Write-Host "$catch - Configuring new RADIUS client side SSO domain"
    add-content -path $logfile -Value "$catch - Configuring new RADIUS client side SSO domain"
    $catch = start-sleep -milliseconds $wait
    }


################################
# Create LDAP Configuration 
################################
if ($Use_LDAP) {
    add-content -path $logfile -Value "`n#### LDAP MFA Configuration ####"
    Write-Host -fore cyan "`nCREATING NEW LDAP CONFIGURATION"
    Write-Host -fore Green "ENTER PASSWORD FOR LDAP SERVER TEST ACCOUNT"
    $TestAccountPass = Read-Host -Prompt  'Please Enter Password for LDAP Auth Server Test Account' -AsSecureString  ## UPDATE - Modify if $Use_LDAP or $Use_Radius is $True. (Password for $ServiceAccount)

    # Create LDAP Service
    $catch = (New-LdapEndpoint -Loadbalancer $LoadmasterIP -Credential $KempCreds -Name $Domain -AdminPass $TestAccountPass -AdminUser $TestAccount -LdapProtocol LDAPS -Server $AuthServers).ReturnCode
    Write-Host "$catch - CREATED NEW LDAP SERVICE CONFIGURATION"
    add-content -path $logfile -Value "$catch - Created LDAP SERVICE Configuration"

    #  CLIENT SIDE SSO DOMAIN - LDAP
    $catch = (New-SSODomain -Loadbalancer $LoadmasterIP -Credential $KempCreds -Domain $Domain).ReturnCode
    Write-Host "$catch - CREATED NEW CLIENT SSO DOMAIN (LDAP)"
    add-content -path $logfile -Value "$catch - CREATED NEW CLIENT SSO DOMAIN (LDAP)"

    # Configure CLIENT SIDE SSO DOMAIN - LDAP
    $catch = (Set-SSODomain -Loadbalancer $LoadmasterIP -Credential $KempCreds -Domain $Domain -logon_domain $Domain -ldap_endpoint $Domain -tls ldaps -auth_type ldap-ldaps -logon_fmt Principalname -sess_tout_idle_pub 1800 -sess_tout_idle_priv 1800 -ldapephc 1).ReturnCode
    Write-Host "$catch - CONFIGURED NEW CLIENT SSO DOMAIN (LDAP)"
    add-content -path $logfile -Value "$catch - CONFIGURED NEW CLIENT SSO DOMAIN (LDAP)"
    $catch = start-sleep -milliseconds $wait
    }

################################
# Create SAML Configuration 
################################
if ($Use_SAML) {
    add-content -path $logfile -Value "`n#### SAML MFA Configuration ####"
    Write-Host -fore cyan "`nCREATING NEW SAML CONFIGURATION"
    add-content -path $logfile -value "CREATING NEW SAML CONFIGURATION"

    # Create new SSO Server Side SAML Domain
    $catch = (New-SSODomain -Loadbalancer $LoadmasterIP -Credential $KempCreds -Domain $Domain).ReturnCode
    Write-Host "$catch - Creating new SAML client side SSO domain"
    add-content -path $logfile -Value "$catch - Creating new SAML client side SSO domain"

    # Configure new SSO Server side SAML Domain
    $Catch = (Set-SSODomain -Loadbalancer $LoadmasterIP -Credential $KempCreds -auth_type SAML -Domain $Domain).ReturnCode 
    add-content -path $logfile -Value "$catch - Configuring SAML SSO domain"
    Write-Host "$catch - Configuring SAML SSO domain"
    start-sleep -Milliseconds $wait

    # Install SAML MetaFile
    $catch = (Install-SAMLIdpMetafile -Loadbalancer $LoadmasterIP -Credential $KempCreds -Path $scripthome\$SAMLmetadata -Domain $Domain).ReturnCode
    Write-Host "$catch - Installing SAML Metafile"
    add-content -path $logfile -Value "$catch - Installing SAML Metafile"
    start-sleep -Milliseconds $wait

    # Configuring SAML SP Certname
    $catch = (Set-SAMLSPEntity -Loadbalancer $LoadmasterIP -Credential $KempCreds -IdpCert $SAMLIDPCertName -Domain $Domain).ReturnCode
    add-content -path $logfile -Value "$catch - Setting Certname for SAML SP"
    Write-Host "$catch - Setting Certname for SAML SP"
    start-sleep -Milliseconds $wait

    # Setting SAML Entity ID
    $catch = (Set-SAMLSPEntity -Loadbalancer $LoadmasterIP -Credential $KempCreds -SPEntityId $SAMLSPEntityID -Domain $Domain).ReturnCode 
    add-content -path $logfile -Value "$catch - Setting Entity ID for SAML SP"
    Write-Host "$catch - Setting Entity ID for SAML SP"
    start-sleep -Milliseconds $wait
    }

###############################
# Create Content Matching Rules
###############################
Add-Content -Path $logfile -Value "CREATING CONTENT MATCHING RULES"
Write-Host -fore cyan "`nCREATING CONTENT MATCHING RULES"

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_Auth" -MatchType regex -NoCase $true -Pattern "/^\/Citrix\/.*Auth\/.*|^\/Citrix\/.*\/CitrixAuth\/Login.*|\/Citrix\/.*\/ExplicitAuth\/AllowSelfServiceAccountManagement.*|\/Citrix\/.*\/Resources\/List.*/").ReturnCode
Write-Host "$catch - Create Citrix_Auth Rule"
add-content -path $logfile -Value "$catch = Create Citrix_Auth Rule"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_Auth_Cookie" -MatchType regex -Header Cookie -Pattern "CtxsAuthId" -NoCase $true -OnlyOnFlag 2).ReturnCode
Write-Host "$catch - Create Citrix_Auth_Cookie Rule"
add-content -path $logfile -Value "$catch - Create Citrix_Auth_Cookie Rule"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_LMDATA_Cookie" -MatchType regex -Header Cookie -Pattern "lmdata" -NoCase $true -SetFlagOnMatch 2).ReturnCode
Write-Host "$catch - Citrix_LMDATA_Cookie"
add-content -path $logfile -Value "$catch - Citrix_LMDATA_Cookie"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_LM_Auth_Proxy"-MatchType regex -NoCase $true -Pattern "/^\/lm_auth_proxy.*/").ReturnCode
Write-Host "$catch - Citrix_LM_Auth_Proxy"
add-content -path $logfile -Value "$catch - Citrix_LM_Auth_Proxy"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_Logout" -MatchType regex -Pattern "/^\/Citrix\/.*\/Authentication\/Logoff.*/" -NoCase $true -SetFlagOnMatch 3).ReturnCode
Write-Host "$catch - Citrix_Logout"
add-content -path $logfile -Value "$catch - Citrix_Logout"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_Receiver_Useragent" -MatchType regex -Header User-Agent -Pattern "/^CitrixReceiver.*|CitrixWorkspace.*/"-NoCase $true).ReturnCode
Write-Host "$catch - Citrix_Receiver_Useragent"
add-content -path $logfile -Value "$catch - Citrix_Receiver_Useragent"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_Useragent_Desktop_Receiver" -MatchType regex -Header User-Agent -Pattern "/^CitrixReceiver.*SelfService.*|SelfService.*/"-NoCase $true -Negate $true -SetFlagOnMatch 2).ReturnCode
Write-Host "$catch - Citrix_Useragent_Desktop_Receiver"
add-content -path $logfile -Value "$catch - Citrix_Useragent_Desktop_Receiver"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_Download_ICA_File" -MatchType regex -IncQuery $True -Pattern /^\/Citrix\/.*Web\/Resources\/LaunchIca\/.*CsrfToken.*/ -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_Download_ICA_File"
add-content -path $logfile -Value "$catch - Citrix_Download_ICA_File"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_WorkSpace_Receiver_PreAuth" -MatchType regex -IncQuery $True -Pattern /^\/Citrix\/kempstoreAuth\/ExplicitForms$/ -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_WorkSpace_Receiver_PreAuth"
add-content -path $logfile -Value "$catch - Citrix_WorkSpace_Receiver_PreAuth"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_PNAgent_Store" -MatchType regex -Pattern "/^\/citrix\/store\/pnagent.*/" -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_PNAgent_Store"
add-content -path $logfile -Value "$catch - Citrix_PNAgent_Store"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName "Citrix_PNAgent_LaunchApp" -MatchType regex -Pattern "/^\/citrix\/store\/pnagent\/launch.aspx$/" -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_PNAgent_LaunchApp"
add-content -path $logfile -Value "$catch - Citrix_PNAgent_LaunchApp"
$catch = start-sleep -milliseconds $wait

##################################
# Create Header Modification Rules
##################################
add-content -path $logfile -Value "`n#### Create Header Modification Rules ####"
write-host -fore cyan "`nCREATING HEADER MODIFICATION RULES"

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_AcceptEncoding -Type 2 -Pattern Accept-Encoding).ReturnCode
write-host "$catch - Citrix_AcceptEncoding"
add-content -path $logfile -Value "$catch - Citrix_AcceptEncoding"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_Browser_URL -Type 4 -Pattern /^\/$/ -Replacement $StorePath).ReturnCode
write-host "$catch - Citrix_Browser_URL"
add-content -path $logfile -Value "$catch - Citrix_Browser_URL"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_Delete_CtxAithID -Type 1 -Header Set-Cookie -Replacement "CtxsAuthId=*; expires=Thu, 14-Jun-1990 16:53:03 GMT; path=$StorePath/; secure" -OnlyOnFlag 3).ReturnCode
write-host "$catch - Citrix_Delete_CtxAithID"
add-content -path $logfile -Value "$catch - Citrix_Delete_CtxAithID"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_HTTPS -Type 1 -Header X-Citrix-IsUsingHTTPS -Replacement Yes).ReturnCode
write-host "$catch - Citrix_HTTPS"
add-content -path $logfile -Value "$catch - Citrix_HTTPS"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_HTTP_200_To_302 -Type 4 -Pattern "200 OK" -Replacement "301 Moved Permanently").ReturnCode
write-host "$catch - Citrix_HTTP_200_To_302"
add-content -path $logfile -Value "$catch - Citrix_HTTP_200_To_302"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_Redirect -Type 1 -Header Location -Replacement "https://$FQDN$StorePath/").ReturnCode
write-host "$catch - Citrix_Redirect"
add-content -path $logfile -Value "$catch - Citrix_Redirect"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_Delete_DeviceID -Type 3 -Header Cookie -Pattern "/^CtxsDeviceId=.*\; (.*)\; (.*)/" -Replacement "\1; \2").ReturnCode
write-host "$catch - Citrix_Delete_DeviceID"
add-content -path $logfile -Value "$catch - Citrix_Delete_DeviceID"
$catch = start-sleep -milliseconds $wait

################################
# Create Body Modification Rules
################################
add-content -path $logfile -Value "`n#### Create Body Modification Rules ####"
Write-Host -fore cyan "`nCREATING BODY MODIFICATION RULES"

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_GatewayAddress -Type 5 -Pattern "LongCommandLine="  -Replacement "Address=$FQDN" -OnlyOnFlag 2 -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_GatewayAddress"
add-content -path $logfile -Value "$catch - Citrix_GatewayAddress"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName Citrix_SSL_On -Type 5 -Pattern "SSLEnable=Off" -Replacement "SSLEnable=On" -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_SSL_On"
add-content -path $logfile -Value "$catch - Citrix_SSL_On"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName  Citrix_UDPCGP -Type 5 -Pattern "/UDPCGPPort=.*:2598/" -Replacement "UDPCGPPort=$FQDN" -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_UDPCGP"
add-content -path $logfile -Value "$catch - Citrix_UDPCGP"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName  Citrix_UDPICA -Type 5 -Pattern "/UDPICAPort=.*:1494/" -Replacement "UDPICAPort=$FQDN" -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_UDPICA"
add-content -path $logfile -Value "$catch - Citrix_UDPICA"
$catch = start-sleep -milliseconds $wait

$catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName  Citrix_UDPWebSocket -Type 5 -Pattern "/UDPWebSocketPort=.*:8008/" -Replacement "UDPWebSocketPort=$FQDN" -NoCase $true).ReturnCode
Write-Host "$catch - Citrix_UDPWebSocket"
add-content -path $logfile -Value "$catch - Citrix_UDPWebSocket"
$catch = start-sleep -milliseconds $wait

write-host -fore cyan "`nALL RULES CREATED"

#############################
# Creating Virtual Services #
#############################
Write-Host -fore cyan "`nCREATING VIRTUAL SERVICES"

######################################################
#Create VS - Citrix StoreFront Gateway - HTTP redirect
######################################################
$doit = ((Get-AdcVirtualService -LoadBalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIP -VSPort 80 -VSProtocol tcp).data.vs.nickname -ne "$VSName - HTTP redirect-Test")
if ($doit) {
$catch = (New-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -nickname "$VSName - HTTP redirect-Test" -VSPort 80 -VSProtocol tcp -VSType http).ReturnCode
write-host "$catch - Create VS Citrix StoreFront Gateway - HTTP redirect" 
add-content -path $logfile -Value "$catch - Create VS Citrix StoreFront Gateway - HTTP redirect"
$catch = start-sleep -milliseconds $wait
}
$catch = (Set-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort 80 -VSProtocol tcp -ErrorCode 302 -ErrorUrl https://%h%s -AddVia 5).ReturnCode
write-host "$catch   - Configure VS Citrix StoreFront Gateway - HTTP redirect"
add-content -path $logfile -Value "$catch - Configure VS Citrix StoreFront Gateway - HTTP redirect"
$catch = start-sleep -milliseconds $wait

######################################
# Create VS - Citrix StoreFront Gateway
######################################
$doit = ((Get-AdcVirtualService -LoadBalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIP -VSPort $VSPort -VSProtocol tcp).data.vs.nickname -ne "$VSName")

# Create VS
if ($doit) {
$VS = (New-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -nickname $VSName -VSPort $VSPort -VSProtocol tcp -VSType http)
$VSIndex = $VS.data.VS.Index
$catch = $VS.ReturnCode
write-host "$catch - Create VS Citrix StoreFront Gateway"
add-content -path $logfile -Value "$catch - Create VS Citrix StoreFront Gateway"
$catch = start-sleep -milliseconds $wait
}
# Configure VS
$Catch = (Set-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -nickname $VSName -VSPort $VSPort -VSProtocol tcp -SSLAcceleration $true -SSLReencrypt $true -CertFile $CertName).ReturnCode
write-host "$catch   - Configure VS Citrix StoreFront Gateway"
add-content -path $logfile -Value "$catch - Configure VS Citrix StoreFront Gateway"
$catch = start-sleep -milliseconds $wait


#############################
# Assign HTTP Selection Rules 

if ($USE_ESP) {
    # Citrix_Logout
    $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RuleType pre -RuleName Citrix_Logout).ReturnCode
    write-host "$catch   - Assign request rule Citrix_Logout"
    add-content -path $logfile -Value "$catch - Assign request rule Citrix_Logout"
    $catch = start-sleep -milliseconds $wait

    # Citrix_LMDATA_Cookie
    $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RuleType pre -RuleName Citrix_LMDATA_Cookie).ReturnCode
    write-host "$catch   - Assign request rule Citrix_LMDATA_Cookie"
    add-content -path $logfile -Value "$catch - Assign request rule Citrix_LMDATA_Cookie"
    $catch = start-sleep -milliseconds $wait
    }

##################################
# Assign HTTP Header Modifications

# Citrix_Browser_URL
$catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RuleType request -RuleName Citrix_Browser_URL).ReturnCode
write-host "$catch   - Assign request rule Citrix_Browser_URL"
add-content -path $logfile -Value "$catch - Assign request rule Citrix_Browser_URL"
$catch = start-sleep -milliseconds $wait


if ($Use_ESP) {
    # Citrix_Delete_CtxAithID
    $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RuleType response -RuleName Citrix_Delete_CtxAithID).ReturnCode
    write-host "$catch   - Assign request rule Citrix_Delete_CtxAithID"
    add-content -path $logfile -Value "$catch - Assign request rule Citrix_Delete_CtxAithID"
    $catch = start-sleep -milliseconds $wait
    } 


#############################
# Create Sub Virtual Services
#############################
add-content -path $logfile -Value "`n#### Create Sub Virtual Services ####"


if ($Use_ESP) {
    ##################################
    #SubVS StoreFront Browser Auth ESP
    ##################################
    $StoreFrontBrowserAuthESP = (New-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $VSIndex)
    $catch = $StoreFrontBrowserAuthESP.ReturnCode
    $StoreFrontBrowserAuthESPIndex = ($StoreFrontBrowserAuthESP.Data.VS.SubVS[-1]).VSIndex
    $StoreFrontBrowserAuthESPIndexRS = $StoreFrontBrowserAuthESP.Data.VS.SubVS.RSIndex
    write-host "$catch - Create SubVS StoreFront Browser Auth ESP"
    add-content -path $logfile -Value "$catch - Create SubVS StoreFront Browser Auth ESP"

    $catch = (Set-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontBrowserAuthESPIndex -Persist cookie -cookie "CtxsAuthId" -PersistTimeout 3600 -CheckPort $RSPort -CheckType https -CheckUrl $StorePath -CheckUse1_1 1 -Nickname "StoreFront Browser Auth ESP" -VSType http -Weight 1000 -AddVia 5).ReturnCode
    write-host "$catch   - Configure SubVS StoreFront Browser Auth ESP"
    add-content -path $logfile -Value "$catch - Configure SubVS StoreFront Browser Auth ESP"
    $catch = start-sleep -milliseconds $wait

    ############
    # Enable ESP
    add-content -path $logfile -Value "## Enable ESP"

    $catch = (Set-AdcSubVirtualService  -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontBrowserAuthESPIndex -ESPEnabled $true -InputAuthMode 2 -AllowedHosts $FQDN -AllowedDirectories "/*" -OutputAuthMode 2).ReturnCode
    write-host "$catch   - Configure SubVS StoreFront Browser Auth ESP Step 1"
    add-content -path $logfile -Value "$catch - Configure SubVS StoreFront Browser Auth ESP"
    $catch = start-sleep -milliseconds $wait

    $catch = (Set-AdcSubVirtualService  -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontBrowserAuthESPIndex -Domain $Domain -ServerFbaPath "$StorePath/PostCredentialsAuth/Login" -Logoff $StorePath/Authentication/Logoff).ReturnCode
    write-host "$catch   - Configure SubVS StoreFront Browser Auth ESP Step 2"
    add-content -path $logfile -Value "$Catch - Configure SubVS StoreFront Browser Auth ESP"
    $catch = start-sleep -milliseconds $wait

    #################################
    # Add a Real Server to the SubVS
    add-content -path $logfile -Value "## Add Real Servers"

    for ($i=0; $i -lt $StoreFrontIP.Count; $i++) {
        $ip = $StoreFrontIP[$i]
        $catch = (New-AdcRealServer -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserAuthESPIndex -RealServer $ip -RealServerPort $RSPort -Enable $true -Forward nat -Weight 1000 -Non_Local $true).ReturnCode
        write-host "$catch   - Add Server $ip to SubVS"
        add-content -path $logfile -Value "$catch  -- Add Server $ip to SubVS"
        $catch = start-sleep -milliseconds $wait
        }
 
    
    ########################################
    # Assign HTTP Header Modifications Rules

    if (-not $Use_SAML) {

        # Citrix_HTTPS
        $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserAuthESPIndex -RuleType request -RuleName Citrix_HTTPS).ReturnCode
        write-host "$catch   - Add request rule Citrix_HTTPS"
        add-content -path $logfile -Value "$catch -- Add request rule Citrix_HTTPS"
        $catch = start-sleep -milliseconds $wait

        # Citrix_AcceptEncoding
        $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserAuthESPIndex -RuleType request -RuleName Citrix_AcceptEncoding).ReturnCode
        write-host "$catch   - Add request rule Citrix_AcceptEncoding"
        add-content -path $logfile -Value "  -- Add request rule Citrix_AcceptEncoding.ReturnCode"
        $catch = start-sleep -milliseconds $wait

        # Citrix_HTTP_200_To_302
        $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserAuthESPIndex -RuleType response -RuleName Citrix_HTTP_200_To_302).ReturnCode
        write-host "$catch   - Add request rule Citrix_HTTP_200_To_302"
        add-content -path $logfile -Value " $Catch -- Add request rule Citrix_HTTP_200_To_302"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Redirect
        $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserAuthESPIndex -RuleType response -RuleName Citrix_Redirect).ReturnCode
        write-host "$catch   - Add request rule Citrix_HTTP_Redirect"
        add-content -path $logfile -Value " $Catch -- Add request rule Citrix_Redirect"
        $catch = start-sleep -milliseconds $wait
        }
    }

###########################################
# SubVS StoreFront Browser Launch HTML5 App
###########################################
if ($Use_HTML5) {
    $StoreFrontBrowserLaunchHTML5App = (New-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $VSIndex)
    $catch = $StoreFrontBrowserLaunchHTML5App.ReturnCode
    $StoreFrontBrowserLaunchHTML5AppIndex =   ($StoreFrontBrowserLaunchHTML5App.Data.VS.SubVS[-1]).VSIndex
    $StoreFrontBrowserLaunchHTML5AppIndexRS = ($StoreFrontBrowserLaunchHTML5App.Data.VS.SubVS[-1]).RSIndex
    write-host "$catch - Create SubVS StoreFront Browser Launch HTML5 App"
    add-content -path $logfile -Value "$catch - Create SubVS StoreFront Browser Launch HTML5 App"
 
    $catch = (Set-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontBrowserLaunchHTML5AppIndex -Persist cookie -cookie "CtxsAuthId" -PersistTimeout 3600 -CheckPort $RSPort -CheckType https -CheckUrl $StorePath -CheckUse1_1 1 -Nickname "StoreFront Browser Launch HTML5 App" -VSType http -Weight 1000 -AddVia 5).ReturnCode
    write-host "$catch   - Configure SubVS StoreFront Browser Launch HTML5 App"
    add-content -path $logfile -Value "$Catch - Configure SubVS StoreFront Browser Launch HTML5 App"
    $catch = start-sleep -milliseconds $wait

    ####################
    # Add a Real Servers
    for ($i=0; $i -lt $StoreFrontIP.Count; $i++) {
        $ip = $StoreFrontIP[$i]
        $catch = (New-AdcRealServer -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserLaunchHTML5AppIndex -RealServer $ip -RealServerPort $RSPort -Enable $true -Forward nat -Weight 1000 -Non_Local $true).ReturnCode
        write-host "$catch   - Adding StoreFront Server $ip"
        add-content -path $logfile -Value "$Catch -- Adding StoreFront Server $ip"
        $catch = start-sleep -milliseconds $wait
        }
 

    #############################
    # Assign HTTP Selection Rules

    # Citrix_Useragent_Desktop_Receiver
    $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserLaunchHTML5AppIndex -RuleType pre -RuleName Citrix_Useragent_Desktop_Receiver).ReturnCode
    write-host "$catch   - Assigning HTTP Selection Rule: Citrix_Useragent_Desktop_Receiver"
    add-content -path $logfile -Value "$catch - Assigning HTTP Selection Rule: Citrix_Useragent_Desktop_Receiver"
    $catch = start-sleep -milliseconds $wait

    ########################################
    # Assign HTTP Header Modifications Rules

    # Citrix_AcceptEncoding
    $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontBrowserLaunchHTML5AppIndex -RuleType request -RuleName Citrix_AcceptEncoding).ReturnCode
    write-host "$catch   - Assigning HTTP Selection Rule: Citrix_AcceptEncoding"
    add-content -path $logfile -Value "$catch - Assigning HTTP Selection Rule: Citrix_AcceptEncoding"
    $catch = start-sleep -milliseconds $wait

    #########################################
    # Assign Response Body Modification Rules

    }
 
################################################
#SubVS StoreFront Workspace-Receiver Add Account
################################################

$StoreFrontWorkspaceReceiverAddAccount = (New-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $VSIndex)
$catch = $StoreFrontWorkspaceReceiverAddAccount.ReturnCode
$StoreFrontWorkspaceReceiverAddAccountIndex = ($StoreFrontWorkspaceReceiverAddAccount.Data.VS.SubVS[-1]).VSIndex
$StoreFrontWorkspaceReceiverAddAccountIndexRS = ($StoreFrontWorkspaceReceiverAddAccount.Data.VS.SubVS[-1]).RSIndex
Write-Host "$catch - Create SubVS: StoreFront Workspace Receiver Add Account"
add-content -path $logfile -Value "$catch - Create SubVS: StoreFront Workspace-Receiver Add Account"
 
$catch = start-sleep -milliseconds $wait
$catch = (Set-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontWorkspaceReceiverAddAccountIndex -Persist cookie -cookie "CtxsAuthId" -PersistTimeout 3600 -CheckPort $RSPort -CheckType https -CheckUrl $StorePath -CheckUse1_1 1 -Nickname "StoreFront Workspace-Receiver Add Account" -VSType http -Weight 1000 -AddVia 5).ReturnCode
Write-Host "$catch   - Configure SubVS: StoreFront Workspace Receiver Add Account"
add-content -path $logfile -Value "$catch - Configure SubVS: StoreFront Workspace-Receiver Add Account"
$catch = start-sleep -milliseconds $wait
 
####################
# Add a Real Servers
for ($i=0; $i -lt $StoreFrontIP.Count; $i++) {
    $ip = $StoreFrontIP[$i]
    $catch = (New-AdcRealServer -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontWorkspaceReceiverAddAccountIndex -RealServer $ip -RealServerPort $RSPort -Enable $true -Forward nat -Weight 1000 -Non_Local $true).ReturnCode
    write-host "$catch   - Add Server $ip to SubVS"
    add-content -path $logfile -Value "$Catch -- Add Server $ip to SubVS"
    $catch = start-sleep -milliseconds $wait
    }


#############################
# Add Content Matching Rules

####################################
# Add HTTP Header Modification Rules

# Citrix_Delete_DeviceID
$catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontWorkspaceReceiverAddAccountIndex -RuleType request -RuleName Citrix_Delete_DeviceID).ReturnCode
write-host "$catch   - Adding HTTP Header Modification Rule: Citrix_Delete_DeviceID"
add-content -path $logfile -Value "$catch - Adding HTTP Header Modification Rule: Citrix_Delete_DeviceID"
$catch = start-sleep -milliseconds $wait


################################################
# SubVS StoreFront Workspace-Receiver Launch App
################################################
$StoreFrontWorkspaceReceiverLaunchApp = (New-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $VSIndex)
$catch = $StoreFrontWorkspaceReceiverLaunchApp.ReturnCode
$StoreFrontWorkspaceReceiverLaunchAppIndex = ($StoreFrontWorkspaceReceiverLaunchApp.Data.VS.SubVS[-1]).VSIndex
$StoreFrontWorkspaceReceiverLaunchAppRS = ($StoreFrontWorkspaceReceiverLaunchApp.Data.VS.SubVS[-1]).RSIndex
Write-Host "$catch - Create SubVS:StoreFront Workspace Receiver Launch App"
add-content -path $logfile -Value "$catch - Create SubVS:StoreFront Workspace Receiver Launch App"
 
$catch = (Set-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontWorkspaceReceiverLaunchAppIndex -Persist cookie -cookie "CtxsAuthId" -PersistTimeout 3600 -CheckPort $RSPort -CheckType https -CheckUrl $StorePath -CheckUse1_1 1 -Nickname "StoreFront Workspace-Receiver Launch App" -VSType http -Weight 1000 -AddVia 5).ReturnCode
Write-Host "$catch   - Configure SubVS:StoreFront Workspace Receiver Launch App"
add-content -path $logfile -Value "$catch - Configure SubVS:StoreFront Workspace Receiver Launch App"
$catch = start-sleep -milliseconds $wait

add-content -path $logfile -Value "## Add Real Servers"
####################
# Add a Real Servers
for ($i=0; $i -lt $StoreFrontIP.Count; $i++) {
    $ip = $StoreFrontIP[$i]
    $catch = (New-AdcRealServer -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontWorkspaceReceiverLaunchAppIndex -RealServer $ip -RealServerPort $RSPort -Enable $true -Forward nat -Weight 1000 -Non_Local $true).ReturnCode
    add-content -path $logfile -Value " - Adding $ip"
    write-host "$catch   - Adding StoreFront Server $ip"
    $catch = start-sleep -milliseconds $wait
    }


#############################
## Add Content Matching Rules

################################
# HTTP Header Modification Rules
#
# Citrix_Useragent_Desktop_Receiver
$catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontWorkspaceReceiverLaunchAppIndex -RuleType pre -RuleName Citrix_Useragent_Desktop_Receiver).ReturnCode
write-host "$catch   - Assigning HTTP Header Modification Rule: Citrix_Useragent_Desktop_Receiver"
add-content -path $logfile -Value "$catch - Assigning HTTP Header Modification Rule: Citrix_Useragent_Desktop_Receiver"
$catch = start-sleep -milliseconds $wait
#
# Citrix_AcceptEncoding
$catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontWorkspaceReceiverLaunchAppIndex -RuleType request -RuleName Citrix_AcceptEncoding).ReturnCode
write-host "$catch   - Assigning HTTP Header Modification Rule: Citrix_AcceptEncoding"
add-content -path $logfile -Value "$catch - Assigning HTTP Header Modification Rule: Citrix_AcceptEncoding"
$catch = start-sleep -milliseconds $wait


##########################################################################################
# Response Body Modification Rules will be added in the VDI 2598 Listener Virtual Services

if ($Use_ESP) {
    #######################################################
    #SubVS StoreFront Workspace-Receiver Pre-Authentication
    #######################################################

    $StoreFrontWorkspaceReceiverPreAuthentication = (New-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $VSIndex)
    $catch = $StoreFrontWorkspaceReceiverPreAuthentication.ReturnCode
    $StoreFrontWorkspaceReceiverPreAuthenticationIndex = ($StoreFrontWorkspaceReceiverPreAuthentication.Data.VS.SubVS[-1]).VSIndex
    $StoreFrontWorkspaceReceiverPreAuthenticationIndexRS = ($StoreFrontWorkspaceReceiverPreAuthentication.Data.VS.SubVS[-1]).RSIndex

    Write-Host "$catch - Created SubVS: StoreFront Workspace Receiver Add Account"
    add-content -path $logfile -Value "$catch - Created SubVS: StoreFront Workspace Receiver Add Account"
 
    $catch = (Set-AdcSubVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontWorkspaceReceiverPreAuthenticationIndex -Persist cookie -cookie "CtxsAuthId" -PersistTimeout 3600 -CheckPort $RSPort -CheckType https -CheckUrl $StorePath -CheckUse1_1 1 -Nickname "StoreFront Workspace-Receiver Pre-Authentication" -VSType http -Weight 1000 -AddVia 5).ReturnCode
    Write-Host "$catch   - Configure SubVS: Setting core parameters"
    add-content -path $logfile -Value "$catch$catch - Configure SubVS: Setting core parameters"
    $catch = start-sleep -milliseconds $wait

    add-content -path $logfile -Value "## Enable ESP"
    $catch = (Set-AdcSubVirtualService  -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontWorkspaceReceiverPreAuthenticationIndex -ESPEnabled $true -InputAuthMode 7 -AllowedHosts $FQDN -AllowedDirectories "/*" -OutputAuthMode 2).ReturnCode
    Write-Host "$catch   - Configuring SubVS: Enabling ESP Part 1"
    add-content -path $logfile -Value "$catch - Configuring SubVS: Enabling ESP Part 1"
    $catch = start-sleep -milliseconds $wait

    $catch = (Set-AdcSubVirtualService  -Loadbalancer $LoadmasterIP -Credential $KempCreds -SubVSIndex $StoreFrontWorkspaceReceiverPreAuthenticationIndex -Domain $Domain -ServerFbaPath "$StorePath/ExplicitAuth/Login").ReturnCode
    Write-Host "$catch   - Configuring SubVS: Enabling ESP Part 2"
    add-content -path $logfile -Value "$catch$catch - Configuring SubVS: Enabling ESP Part 2"
    $catch = start-sleep -milliseconds $wait
 
    ####################
    # Add a Real Servers
    for ($i=0; $i -lt $StoreFrontIP.Count; $i++) {
        $ip = $StoreFrontIP[$i]
        $catch = (New-AdcRealServer -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontWorkspaceReceiverPreAuthenticationIndex -RealServer $ip -RealServerPort $RSPort -Enable $true -Forward nat -Weight 1000 -Non_Local $true).ReturnCode
        write-host "$catch   - Adding StoreFront Server $ip"
        add-content -path $logfile -Value "$catch$catch - Adding $ip"
        $catch = start-sleep -milliseconds $wait
        }

    ####################################
    # Add HTTP Header Modification Rules

    # Citrix_Delete_DeviceID
    $catch = (New-AdcVirtualServiceRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $StoreFrontWorkspaceReceiverPreAuthenticationIndex -RuleType request -RuleName Citrix_Delete_DeviceID).ReturnCode
    write-host "$catch   - Add HTTP Header Modification Rule: Citrix_Delete_DeviceID"
    add-content -path $logfile -Value "$catch - Add HTTP Header Modification Rule: Citrix_Delete_DeviceID"
    $catch = start-sleep -milliseconds $wait
    }

########################
# Content matching rules
########################

if ($Use_ESP) {

    if ($Use_HTML5) {

        # Citrix_PNAgent_Store
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverAddAccountIndexRS -RuleName Citrix_PNAgent_Store).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_PNAgent_Store"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_PNAgent_Store"
        $catch = start-sleep -milliseconds $wait

        # Citrix__PNAgent_LaunchApp
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_PNAgent_LaunchApp).ReturnCode
        write-host "$catch   - Create New Rule: Citrix__PNAgent_LaunchApp"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix__PNAgent_LaunchApp"
        $catch = start-sleep -milliseconds $wait

        # Citrix_WorkSpace_Receiver_PreAuth
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverPreAuthenticationIndexRS -RuleName Citrix_WorkSpace_Receiver_PreAuth).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_WorkSpace_Receiver_PreAuth"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_WorkSpace_Receiver_PreAuth"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Download_ICA_File
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_Download_ICA_File).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Download_ICA_File"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Download_ICA_File"
        $catch = start-sleep -milliseconds $wait

        # Citrix_LM_Auth_Proxy
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserAuthESPIndexRS -RuleName Citrix_LM_Auth_Proxy).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_LM_Auth_Proxy"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_LM_Auth_Proxy"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Logout
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserAuthESPIndexRS -RuleName Citrix_Logout).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Logout"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Logout"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Auth_Cookie
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserLaunchHTML5AppIndexRS -RuleName Citrix_Auth_Cookie).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Auth_Cookie"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Auth_Cookie"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Auth
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverAddAccountIndexRS -RuleName Citrix_Auth).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Auth"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Auth"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Receiver_Useragent
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_Receiver_Useragent).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Receiver_Useragent"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Receiver_Useragent"
        $catch = start-sleep -milliseconds $wait

        # default
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserAuthESPIndexRS -RuleName default).ReturnCode
        write-host "$catch   - Create New Rule: default"
        add-content -path $logfile -Value "$catch - Create New Rule: default"
        $catch = start-sleep -milliseconds $wait
        }

    #################################################################################################

    if (-NOT $Use_HTML5) {
    
        # Citrix_PNAgent_Store
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverAddAccountIndexRS -RuleName Citrix_PNAgent_Store).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_PNAgent_Store"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_PNAgent_Store"
        $catch = start-sleep -milliseconds $wait

        # Citrix_PNAgent_LaunchApp
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_PNAgent_LaunchApp).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_PNAgent_LaunchApp"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_PNAgent_LaunchApp"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Download_ICA_File
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_Download_ICA_File).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Download_ICA_File"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Download_ICA_File"
        $catch = start-sleep -milliseconds $wait

        # Citrix_WorkSpace_Receiver_PreAuth
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverPreAuthenticationIndexRS -RuleName Citrix_WorkSpace_Receiver_PreAuth).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_WorkSpace_Receiver_PreAuth"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_WorkSpace_Receiver_PreAuth"
        $catch = start-sleep -milliseconds $wait

        # Citrix_LM_Auth_Proxy
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserAuthESPIndexRS -RuleName Citrix_LM_Auth_Proxy).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_LM_Auth_Proxy"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_LM_Auth_Proxy"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Logout
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserAuthESPIndexRS -RuleName Citrix_Logout).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Logout"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Logout"
        $catch = start-sleep -milliseconds $wait

        ## Citrix_Auth_Cookie
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_Auth_Cookie).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Auth_Cookie"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Auth_Cookie"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Auth
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverAddAccountIndexRS -RuleName Citrix_Auth).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Auth"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Auth"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Receiver_Useragent
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_Receiver_Useragent).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Receiver_Useragent"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Receiver_Useragent"
        $catch = start-sleep -milliseconds $wait

        # default
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserAuthESPIndexRS -RuleName default).ReturnCode
        write-host "$catch   - Create New Rule: default"
        add-content -path $logfile -Value "$catch - Create New Rule: default"
        $catch = start-sleep -milliseconds $wait

        }

    }

#################################################################################################

if (-NOT $Use_ESP) {

    if ($Use_HTML5) {

        # Citrix_PNAgent_Store
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverAddAccountIndexRS -RuleName Citrix_PNAgent_Store).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_PNAgent_Store"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_PNAgent_Store"
        $catch = start-sleep -milliseconds $wait

        # Citrix_PNAgent_LaunchApp
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_PNAgent_LaunchApp).ReturnCode
        write-host "$catch   - Create New Rule: Citrix__PNAgent_LaunchApp"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix__PNAgent_LaunchApp"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Download_ICA_File
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_Download_ICA_File).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Download_ICA_File"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Download_ICA_File"
        $catch = start-sleep -milliseconds $wait

        ## Citrix_Auth
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverAddAccountIndexRS -RuleName Citrix_Auth).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Auth"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Auth"
        $catch = start-sleep -milliseconds $wait

        # Citrix_Receiver_Useragent
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName Citrix_Receiver_Useragent).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Receiver_Useragent"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Receiver_Useragent"
        $catch = start-sleep -milliseconds $wait

        # default
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontBrowserLaunchHTML5AppIndexRS  -RuleName default).ReturnCode
        write-host "$catch   - Create New Rule: default"
        add-content -path $logfile -Value "$catch - Create New Rule: default"
        $catch = start-sleep -milliseconds $wait
        }
   ELSE {

        ## Citrix_Auth
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverAddAccountIndexRS -RuleName Citrix_Auth).ReturnCode
        write-host "$catch   - Create New Rule: Citrix_Auth"
        add-content -path $logfile -Value "$catch - Create New Rule: Citrix_Auth"
        $catch = start-sleep -milliseconds $wait

        # default
        $catch = (New-AdcRealServerRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp -RSIndex $StoreFrontWorkspaceReceiverLaunchAppRS -RuleName default).ReturnCode
        write-host "$catch   - Create New Rule: default"
        add-content -path $logfile -Value "$catch - Create New Rule: default"
        $catch = start-sleep -milliseconds $wait

        }

    }

#################################################################################################

add-content -path $logfile -Value "`nSUB-VIRTUAL SERVICES CREATED AND RULES ASSIGNED"

########################################################################
# Completed configuration of Citrix StoreFront Gateway Virtual Service #
########################################################################


##################################
# Create VDI 2598 Secure Listeners
##################################
add-content -path $logfile -Value "CREATING VIRTUAL SERVICES - VDI 2598 Secure Listeners"
Write-Host -fore cyan "`nCREATING VIRTUAL SERVICES - VDI 2598 Secure Listeners"
$citrix_starting_index = $starting_index 
$citrix_vs_starting_port = $starting_port
$VS = (Get-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp)

if ($Use_ESP) { $SubVSIndex = ($VS.Data.VS.SubVS[-2]).VSIndex }
ELSE { $SubVSIndex = ($VS.Data.VS.SubVS[-1]).VSIndex }

for ($i=0; $i -lt $servers.Count; $i++) {
    $index = $citrix_starting_index + $i
    $RuleName = $vdi2589_vs_name + $index
    $Port = $citrix_vs_starting_port + $i 
    $Pattern = "Address=" + $servers[$i] + ":1494"
    $Replacement = "SSLProxyHost=" + $FQDN + ":" + $Port
    $ip = $servers[$i]

    ### Create new VS Secure Listeners
    $catch = (New-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -nickname $RuleName -VSPort $Port -VSProtocol tcp -VSType http -SSLAcceleration $true -SSLReencrypt $false -CertFile $CertName -CheckType none -AddVia 5).ReturnCode
    Write-Host "$catch - Create VDI 2598 Secure Listener"
    add-content -path $logfile -Value "$catch - Create VS: VDI 2598 Secure Listener"
    $catch = start-sleep -milliseconds $wait

    # Configure VS Type = Generic
    $catch = (Set-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $Port -VSProtocol tcp -VSType gen ).ReturnCode
    Write-Host "$catch   - Configure VS Type = Generic"
    add-content -path $logfile -Value "$catch - Configure VS Type = Generic"
    $catch = start-sleep -milliseconds $wait

    # Enable SSL Reencryption and Set Default Gateway for VS
    $catch = (Set-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $Port -VSProtocol tcp -DefaultGW $Def_GW -SSLReencrypt $Reencrypt).returnCode
    Write-Host "$catch   - Enable SSL Reencryption and Set Default Gateway for VS"
    add-content -path $logfile -Value "$catch - Enable SSL Reencryption and Set Default Gateway for VS"
    $catch = start-sleep -milliseconds $wait

    ### Add Real Server to VS
    $catch = (New-AdcRealServer -Loadbalancer $LoadmasterIP -Credential $KempCreds -RealServer $ip -RealServerPort $vdi2589_RS_Port -Non_Local 1 -Enable $true -Forward nat -Weight 1000 -VirtualService $VirtualServiceIp -VSPort $Port -VSProtocol tcp).ReturnCode
    write-host "$catch   - Adding VDI Server $ip"
    add-content -path $logfile -Value "$catch - Adding VDI Server $ip"
    $catch = start-sleep -milliseconds $wait

    ### Create new ICA Rewrite Rules
    $catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName $RuleName -Type 5 -Pattern $Pattern -Replacement $Replacement -NoCase 1).ReturnCode
    write-host "$catch   - New rule: ICA Rewrite Rules"
    add-content -path $logfile -Value "$catch - New rule: ICA Rewrite Rules"
    $catch = start-sleep -milliseconds $wait

    ##################################
    # Response Body Modification Rules
    $catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName $RuleName).ReturnCode
    write-host "$catch   - Assign Response Body Modification Rules"
    add-content -path $logfile -Value "$catch - New Response Body Modification Rules"
    $catch = start-sleep -milliseconds $wait
    }

##################################
# Response Body Modification Rules

# Citrix_GatewayAddress
$catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_GatewayAddress).ReturnCode
write-host "$catch   - Assign Response Body Modification Rule: Citrix_GatewayAddress"
add-content -path $logfile -Value "$catch - New Response Body Modification Rule: Citrix_GatewayAddress"
$catch = start-sleep -milliseconds $wait

# Citrix_SSL_On
$catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_SSL_On).ReturnCode
write-host "$catch   - Assign Response Body Modification Rule: Citrix_SSL_On"
add-content -path $logfile -Value "$catch - New Response Body Modification Rule: Citrix_SSL_On"
$catch = start-sleep -milliseconds $wait


# Citrix_Internal_To_External
$catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_Internal_To_External).ReturnCode
write-host "$catch   - Assign Response Body Modification Rule: Citrix_Internal_To_External"
add-content -path $logfile -Value "$catch - New Response Body Modification Rule: Citrix_Internal_To_External"
$catch = start-sleep -milliseconds $wait

########################################
# Create VDI HTML5 8008 Secure Listeners
########################################
if ($Use_HTML5) {
    add-content -path $logfile -Value "`n##### # Create VDI HTML5 8008 Secure Listeners #####"
    Write-Host -fore cyan "`nCREATING VIRTUAL SERVICE: VDI HTML5 8080 Secure Listeners"

    $citrix_starting_index = $starting_index
    $citrix_vs_starting_port = $port + 1

    $VS = (Get-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $VSPort -VSProtocol tcp)

    if ($Use_ESP) { $SubVSIndex = ($VS.Data.VS.SubVS[-4]).VSIndex }
    ELSE { $SubVSIndex = ($VS.Data.VS.SubVS[-3]).VSIndex }


    for ($i=0; $i -lt $servers.Count; $i++) {
        $RuleName = $vdi8008_vs_name + ($citrix_starting_index + $i)
        $Port = $citrix_vs_starting_port + $i 
        $Pattern = "Address=" + $servers[$i] + ":1494"
        $Replacement = "SSLProxyHost=" + $FQDN + ":" + $Port
        $ip = $servers[$i]

        ### Create new VS Secure Listeners
        $catch = (New-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $Port -nickname $RuleName -VSProtocol tcp -VSType gen -SSLAcceleration $true -CertFile $CertName -CheckType none -AddVia 5).ReturnCode
        Write-Host "$catch - Create Virtual Service: VDI HTML5 8008 Secure Listener $IP"
        add-content -path $logfile -Value "$catch - Create Virtual Service: VS Secure Listener"
        $catch = start-sleep -milliseconds $wait

        # Enable SSL Reencryption and Set Default Gateway for VS
        $catch = (Set-AdcVirtualService -Loadbalancer $LoadmasterIP -Credential $KempCreds -VirtualService $VirtualServiceIp -VSPort $Port -VSProtocol tcp -DefaultGW $Def_GW -SSLReencrypt $Reencrypt).returnCode
        Write-Host "$catch   - Enable SSL Reencryption and Set Default Gateway for VS"
        add-content -path $logfile -Value "$catch - Enable SSL Reencryption and Set Default Gateway for VS"
        $catch = start-sleep -milliseconds $wait

        ### Add Real Server to VS
        add-content -path $logfile -Value "  Adding VDI Server $ip"
        $catch = (New-AdcRealServer -Loadbalancer $LoadmasterIP -Credential $KempCreds -RealServer $ip -RealServerPort $vdi8008_RS_Port -Non_Local 1 -Enable $true -Forward nat -Weight 1000 -VirtualService $VirtualServiceIp -VSPort $Port -VSProtocol tcp).ReturnCode
        Write-Host "$catch   - Add Server: $IP"
        add-content -path $logfile -Value "$catch - Add Server: $IP"
        $catch = start-sleep -milliseconds $wait
    
        ### Create new ICA Rewrite Rules
        add-content -path $logfile -Value "## Create ICA Rule"
        $catch = (New-AdcContentRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -RuleName $RuleName -Type 5 -Pattern $Pattern -Replacement $Replacement -NoCase 1).ReturnCode
        Write-Host "$catch   - Create Rule: ICA Rewrite"
        add-content -path $logfile -Value "$catch - Create Rule: ICA Rewrite"
        $catch = start-sleep -milliseconds $wait

        # Response Body Modification Rules 
        $catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName $RuleName).ReturnCode
        Write-Host "$catch   - Assign Rule: $Rulename"
        add-content -path $logfile -Value "$catch - Assign Rule: $Rulename"
        $catch = start-sleep -milliseconds $wait
        }

    ##################################
    # Response Body Modification Rules

    # Citrix_GatewayAddress
    $catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_GatewayAddress).ReturnCode
    Write-Host "$catch   - Assign Rule: Citrix_GatewayAddress"
    add-content -path $logfile -Value "$catch - Assign Rule: Citrix_GatewayAddress"
    $catch = start-sleep -milliseconds $wait

    # Citrix_SSL_On
    $catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_SSL_On).ReturnCode
    Write-Host "$catch   - Assign Rule: Citrix_SSL_On"
    add-content -path $logfile -Value "$catch - Assign Rule: Citrix_SSL_On"
    $catch = start-sleep -milliseconds $wait

    # Citrix_UDPCGP
    $catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_UDPCGP).ReturnCode
    Write-Host "$catch   - Assign Rule: Citrix_UDPCGP"
    add-content -path $logfile -Value "$catch - Assign Rule: Citrix_UDPCGP"
    $catch = start-sleep -milliseconds $wait

    # Citrix_UDPICA
    $catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_UDPICA).ReturnCode
    Write-Host "$catch   - Assign Rule: Citrix_UDPICA"
    add-content -path $logfile -Value "$catch - Assign Rule: Citrix_UDPICA"
    $catch = start-sleep -milliseconds $wait

    # Citrix_UDPWebSocket
    $catch = (New-AdcVirtualServiceResponseBodyRule -Loadbalancer $LoadmasterIP -Credential $KempCreds -VSIndex $SubVSIndex -RuleName Citrix_UDPWebSocket).ReturnCode
    Write-Host "$catch   - Assign Rule: Citrix_UDPWebSocket"
    add-content -path $logfile -Value "$catch - Assign Rule: Citrix_UDPWebSocket"
    $catch = start-sleep -milliseconds $wait

    }
   
if ($Use_HTML5 -AND $Use_LDAP) { 
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING HTML5 AND ESP (LDAPS) COMPLETED"
    write-host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING HTML5 AND ESP (LDAPS) COMPLETED" 
    }

if ($Use_HTML5 -AND $Use_Radius) {
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING HTML5 AND ESP (RADIUS) COMPLETED"
    Write-Host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING HTML5 AND ESP (RADIUS) COMPLETED" 
    }

if ($Use_HTML5 -AND $Use_SAML) {
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING HTML5 AND ESP (SAML) COMPLETED"
    Write-Host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING HTML5 AND ESP (RADIUS) COMPLETED" 
    }

if ((-NOT $Use_HTML5) -AND $Use_LDAP) {
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING ICA AND ESP (LDAPS) COMPLETED"
    write-host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING ICA AND ESP (LDAPS) COMPLETED" 
    }

if ((-NOT $Use_HTML5) -AND $Use_Radius) {
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING ICA AND ESP (RADIUS) COMPLETED"
    write-host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING ICA AND ESP (RADIUS) COMPLETED" 
    }

if ((-NOT $Use_HTML5) -AND $Use_SAML) {
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING ICA AND ESP (SAML) COMPLETED"
    write-host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING ICA AND ESP (RADIUS) COMPLETED" 
    }

if ($Use_HTML5 -AND (-NOT $Use_ESP)) {
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING HTML5 WITHOUT ESP COMPLETED"
    write-host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES COMPLETED" 
    }

if ((-NOT $Use_HTML5) -AND (-NOT $Use_ESP)) {
    add-content -path $logfile -Value "`nPROVISIONING OF CITRIX VIRTUAL SERVICES USING ICA WITHOUT ESP COMPLETED"
    write-host -fore cyan "`nPROVISIONING OF CITRIX VIRTUAL SERVICES COMPLETED" 
    }

# Warn user that a reboot is required to enable Sare SubVS Persistence Globally
write-host -fore DarkMagenta -BackgroundColor yellow "`nPLEASE REBOOT LOADMASTER TO COMPLETE CITRIX VIRTUAL SERVICE INSTALL`n"
Read-Host -Prompt "Press Enter to close script"

#################
# END OF SCRIPT #
#################


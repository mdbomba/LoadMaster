# LoadMaster API Workflows

Step-by-step recipes for common LoadMaster tasks using the REST API. All examples use APIv2 (JSON POST to `/accessv2`) unless noted.

## Authentication

All APIv2 requests use this pattern:

```bash
curl -sk -X POST "https://$LM_IP/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"<command>", ...}'
```

Or with an API key:

```bash
curl -sk -X POST "https://$LM_IP/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apikey":"<key>","cmd":"<command>", ...}'
```

For brevity, examples below show only the JSON body.

---

## 1. Day-Zero Setup (License a Fresh LoadMaster)

This flow uses APIv1 because the appliance is not fully initialized until licensed.

For repository test runs, use `Kemp1fourall` as the disposable initial `bal`
password unless the user specifies another value. For a deployment not
explicitly identified as a test, prompt the operator for a new `bal` password
before licensing begins, regardless of image or license type.

For the vendor Free image, select the Free license type. If the user explicitly
deploys a non-Free image, ask whether they want a `trial` or `paid` license.
Use the same Progress account credentials for either. Proceed with `trial`
without an Order ID. For `paid`, prompt for a valid Progress Order ID and stop
before licensing if none is provided. Pass the Order ID to both
`alsilicensetypes` and `alsilicense` for the paid flow.

```bash
LM_IP="10.0.0.100"
KEMP_USER="user@example.com"
KEMP_PASS="password"
NEW_PASS="NewSecurePassword1!"

# Step 1: Read the EULA
MAGIC=$(curl -sk "https://$LM_IP/access/readeula" | xmllint --xpath 'string(//Magic)' -)

# Step 2: Accept the EULA
MAGIC2=$(curl -sk "https://$LM_IP/access/accepteula?magic=$MAGIC&type=free" \
  | xmllint --xpath 'string(//Magic)' -)

# Step 3: Accept telemetry EULA
curl -sk "https://$LM_IP/access/accepteula2?magic=$MAGIC2&accept=yes"

# Step 4: Get available license types
curl -sk "https://$LM_IP/access/alsilicensetypes"

# Step 5: License the LoadMaster (online)
curl -sk "https://$LM_IP/access/alsilicense?user=$KEMP_USER&pass=$KEMP_PASS"

# Step 6: Wait for licensing to complete, then set password
sleep 10
curl -sk "https://$LM_IP/access/set_initial_passwd?passwd=$NEW_PASS"

# Step 7: Re-enable the API (REQUIRED after licensing)
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d "{\"apiuser\":\"bal\",\"apipass\":\"$NEW_PASS\",\"cmd\":\"set\",\"param\":\"enableapi\",\"value\":\"yes\"}"
```

**Related endpoints**: `readeula`, `accepteula`, `accepteula2`, `alsilicensetypes`, `alsilicense`, `set_initial_passwd`

---

## 2. Initial Network Configuration

After licensing, configure DNS, NTP, and hostname.

```json
// Set hostname
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"hostname","value":"lb-prod-01"}

// Set DNS nameservers
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"nameserver","value":"8.8.8.8,8.8.4.4"}

// Set NTP server
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"ntphost","value":"pool.ntp.org"}

// Set default gateway
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modiface","iface":"0","gw":"10.0.0.1"}

// Add a static route
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addroute","dest":"192.168.2.0","mask":"255.255.255.0","gw":"10.0.0.254"}
```

**Related endpoints**: `set`, `modiface`, `addroute`, `showroute`

---

## 3. Deploy a Virtual Service with Real Servers

Create a VS for a web application with two backend servers.

```json
// Step 1: Create the virtual service
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addvs",
 "vs":"10.0.0.50","port":"443","prot":"tcp","nickname":"Web App"}

// Step 2: Configure the VS (HTTPS, health checks, persistence)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modvs",
 "vs":"10.0.0.50","port":"443","prot":"tcp",
 "SSLAcceleration":"1","CheckType":"https","CheckUrl":"/health",
 "Persist":"cookie","PersistTimeout":"600","Schedule":"wlc"}

// Step 3: Assign a TLS certificate
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modvs",
 "vs":"10.0.0.50","port":"443","prot":"tcp",
 "CertFile":"my-wildcard-cert"}

// Step 4: Add real server 1
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addrs",
 "vs":"10.0.0.50","port":"443","prot":"tcp",
 "rs":"192.168.1.10","rsport":"8443","weight":"1000"}

// Step 5: Add real server 2
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addrs",
 "vs":"10.0.0.50","port":"443","prot":"tcp",
 "rs":"192.168.1.11","rsport":"8443","weight":"1000"}

// Step 6: Verify the configuration
{"apiuser":"bal","apipass":"PASSWORD","cmd":"showvs",
 "vs":"10.0.0.50","port":"443","prot":"tcp"}
```

**Related endpoints**: `addvs`, `modvs`, `addrs`, `modrs`, `showvs`, `showrs`, `listvs`

---

## 4. Certificate Management

For the tested fresh KVM test-appliance and management-WUI certificate process,
including local certificate sources and cleanup requirements, see
`TEST-LOADMASTER-RUNBOOK.md`.

### Upload a certificate

```json
{"apikey":"API_KEY","cmd":"addcert",
 "cert":"my-cert","password":"PFX_PASSWORD","replace":"1",
 "data":"<base64-encoded PEM bundle including key and chain>"}
```

### Upload an intermediate CA

```json
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addintermediate",
 "cert":"my-intermediate",
 "certfile":"<base64-encoded PEM content>"}
```

### Request a Let's Encrypt certificate

```json
// Register an account first
{"apiuser":"bal","apipass":"PASSWORD","cmd":"registeracmeaccount"}

// Request the certificate
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addlecert",
 "domain":"www.example.com"}

// Renew later
{"apiuser":"bal","apipass":"PASSWORD","cmd":"renewlecert",
 "domain":"www.example.com"}
```

### List installed certificates

```json
{"apiuser":"bal","apipass":"PASSWORD","cmd":"listcert"}
```

**Related endpoints**: `addcert`, `delcert`, `addintermediate`, `listcert`, `readcert`, `addlecert`, `renewlecert`, `listlecert`, `backupcert`, `restorecert`

---

## 5. STIG Security Hardening

Apply DoD STIG security controls to a LoadMaster. These are the key parameters set by the STIG hardening script.

```json
// Session management
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"sessioncontrol","value":"yes"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"sessionbasicauth","value":"0"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"sessionidletime","value":"600"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"sessionmaxfailattempts","value":"5"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"sessionconcurrent","value":"3"}

// TLS hardening
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"WUITLSProtocols","value":"7"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"WUITLS13Ciphersets","value":"TLS_AES_256_GCM_SHA384 TLS_AES_128_GCM_SHA256"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"WUICipherset","value":"FIPS2"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"OutboundCipherset","value":"FIPS2"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"sslrenegotiate","value":"0"}

// Network security
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"nonlocalrs","value":"yes"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"subnetorigin","value":"yes"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"multigw","value":"1"}

// Logging and auth
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"KcdCipherSha1","value":"yes"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"CEFMsgFormat","value":"yes"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"adminclientaccess","value":"1"}

// Disable call-home (if allowed by license type)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"Tethering","value":"0"}

// Disable GEO port 53 listener (if not using GSLB)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"disablegeo"}

// USG warning banners
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"SSHPreAuth",
 "value":"You are accessing a U.S. Government (USG) Information System..."}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"WUIPreauth",
 "value":"<p style='text-align:center;font-weight:bold'>You are accessing a U.S. Government (USG) Information System...</p>"}
```

**Note**: The `WUIPreauth` banner is ~1800 characters of HTML. Use APIv2 -- APIv1 will silently fail due to URL length limits.

**Related endpoints**: `set`, `get`, `getall`, `modifycipherset`, `disablegeo`

---

## 6. High Availability Setup

Configure an HA pair of LoadMasters.

```json
// On BOTH units: Set the shared secret
{"apiuser":"bal","apipass":"PASSWORD","cmd":"setlmcommsecret","secret":"MySharedSecret123"}

// On Unit 1: Set as first HA
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"hamode","value":"1"}

// Reboot Unit 1
{"apiuser":"bal","apipass":"PASSWORD","cmd":"reboot"}

// After reboot, on Unit 1: Set partner address and shared IP
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modiface","iface":"0","partner":"10.0.0.102"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modiface","iface":"0","shared":"10.0.0.100"}

// On Unit 2: Set as second HA
{"apiuser":"bal","apipass":"PASSWORD","cmd":"set","param":"hamode","value":"2"}

// Reboot Unit 2
{"apiuser":"bal","apipass":"PASSWORD","cmd":"reboot"}

// After reboot, on Unit 2: Set partner address and shared IP
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modiface","iface":"0","partner":"10.0.0.101"}
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modiface","iface":"0","shared":"10.0.0.100"}

// Force sync from active to standby
{"apiuser":"bal","apipass":"PASSWORD","cmd":"forceupdatepartner"}
```

**Related endpoints**: `setlmcommsecret`, `set` (hamode), `modiface`, `reboot`, `forceupdatepartner`

---

## 7. Content Rules and L7 Switching

Create content rules to route traffic based on URL or headers.

```json
// Create a match rule (route /api/* to a specific SubVS)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addrule",
 "name":"api-route","type":"0","pattern":"/api/.*"}

// Create a header injection rule
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addrule",
 "name":"add-x-forwarded","type":"1",
 "header":"X-Forwarded-Proto","pattern":"https"}

// Assign rules to a virtual service
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addprerule",
 "vs":"10.0.0.50","port":"443","prot":"tcp","rule":"api-route"}

{"apiuser":"bal","apipass":"PASSWORD","cmd":"addresponserule",
 "vs":"10.0.0.50","port":"443","prot":"tcp","rule":"add-x-forwarded"}
```

**Related endpoints**: `addrule`, `modrule`, `delrule`, `showrule`, `addprerule`, `addrequestrule`, `addresponserule`, `addresponsebodyrule`

---

## 8. WAF (Web Application Firewall)

Enable OWASP WAF protection on a virtual service.

```json
// Enable OWASP WAF on a VS (blocking mode, paranoia level 2)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"modvs",
 "vs":"10.0.0.50","port":"443","prot":"tcp",
 "InterceptMode":"1","OwaspOpts":"1","BlockingParanoiaLevel":"2"}

// Assign specific WAF rulesets
{"apiuser":"bal","apipass":"PASSWORD","cmd":"vsaddwafrule",
 "vs":"10.0.0.50","port":"443","prot":"tcp",
 "rule":"crs-setup.conf,REQUEST-901-INITIALIZATION.conf,REQUEST-941-APPLICATION-ATTACK-XSS.conf,REQUEST-942-APPLICATION-ATTACK-SQLI.conf"}

// Upload a custom WAF rule
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addowaspcustomrule",
 "name":"my-custom-rule","file":"<base64-encoded rule content>"}

// Check WAF settings
{"apiuser":"bal","apipass":"PASSWORD","cmd":"getwafsettings"}
```

**Related endpoints**: `modvs`, `vsaddwafrule`, `vsremovewafrule`, `vslistwafruleids`, `addowaspcustomrule`, `owasprules`, `getwafsettings`, `listwafrules`

---

## 9. Backup and Restore

```json
// Create a backup (returns base64-encoded configuration)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"backup"}

// Restore from backup
{"apiuser":"bal","apipass":"PASSWORD","cmd":"restore",
 "file":"<base64-encoded backup data>"}

// Backup certificates separately
{"apiuser":"bal","apipass":"PASSWORD","cmd":"backupcert"}

// Restore certificates
{"apiuser":"bal","apipass":"PASSWORD","cmd":"restorecert",
 "file":"<base64-encoded cert backup>"}
```

**Related endpoints**: `backup`, `restore`, `backupcert`, `restorecert`

---

## 10. Monitoring and Troubleshooting

### Check appliance health

```json
// Get system statistics (CPU, memory, TPS)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"stats"}

// Get VS/RS status totals
{"apiuser":"bal","apipass":"PASSWORD","cmd":"vstotals"}

// Show a specific VS and its real servers
{"apiuser":"bal","apipass":"PASSWORD","cmd":"showvs",
 "vs":"10.0.0.50","port":"443","prot":"tcp"}
```

### Network diagnostics

```json
// Ping a backend server
{"apiuser":"bal","apipass":"PASSWORD","cmd":"logging.ping","addr":"192.168.1.10"}

// Traceroute
{"apiuser":"bal","apipass":"PASSWORD","cmd":"logging.traceroute","addr":"192.168.1.10"}

// Run a top (4 samples, 3 second interval)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"logging.top","iterations":"4","interval":"3"}
```

### Log management

```json
// List system log files
{"apiuser":"bal","apipass":"PASSWORD","cmd":"logging.listsyslogfiles"}

// Save logs (returns base64 content)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"logging.savelogs"}

// Save a specific log file
{"apiuser":"bal","apipass":"PASSWORD","cmd":"logging.savelogs","fsel":"messages"}

// Reset statistics
{"apiuser":"bal","apipass":"PASSWORD","cmd":"logging.resetstats"}
```

**Related endpoints**: `stats`, `vstotals`, `showvs`, `showrs`, `logging.ping`, `logging.traceroute`, `logging.top`, `logging.listsyslogfiles`, `logging.savelogs`, `logging.resetstats`

---

## 11. User and Access Management

```json
// Create a local admin user (read-write permissions)
{"apiuser":"bal","apipass":"PASSWORD","cmd":"useraddlocal",
 "user":"apiuser","password":"SecurePass1!","perms":"2"}

// Generate an API key
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addapikey"}

// Create a remote LDAP group with full admin
{"apiuser":"bal","apipass":"PASSWORD","cmd":"groupaddremote",
 "group":"LM-Admins","perms":"3"}

// Add an LDAP endpoint
{"apiuser":"bal","apipass":"PASSWORD","cmd":"addldapendpoint",
 "name":"corp-ldap","server":"ldap.example.com","protocol":"ldaps"}
```

**Related endpoints**: `useraddlocal`, `userdellocal`, `usersetperms`, `addapikey`, `delapikey`, `groupaddremote`, `addldapendpoint`

---

## 12. SSO Domain Configuration

```json
// Create an SSO domain with LDAP authentication
{"apiuser":"bal","apipass":"PASSWORD","cmd":"adddomain",
 "domain":"sso.example.com","auth_type":"LDAP"}

// Configure the domain
{"apiuser":"bal","apipass":"PASSWORD","cmd":"moddomain",
 "domain":"sso.example.com",
 "max_failed_auths":"5","sess_tout_idle":"1800","sess_tout_duration":"28800"}

// List active sessions
{"apiuser":"bal","apipass":"PASSWORD","cmd":"ssodomain.queryall",
 "domain":"sso.example.com"}

// Kill all sessions for the domain
{"apiuser":"bal","apipass":"PASSWORD","cmd":"ssodomain.killallsessions",
 "domain":"sso.example.com"}
```

**Related endpoints**: `adddomain`, `moddomain`, `showdomain`, `deldomain`, `ssodomain.queryall`, `ssodomain.search`, `ssodomain.killsession`, `ssodomain.killallsessions`

# Kemp LoadMaster API Knowledge Base

## Sources

- **loadmaster_api.pdf** (local, not machine-readable)
- **PowerShell SDK vNext** (`powershell-sdk-vnext-master/`) -- full 28,000-line `.psm1` module, `.psd1` manifest, help XML (172K lines), examples, changelog
- **GitHub: KEMPtechnologies/powershell-sdk-vnext** -- 91 commits, last updated Jul 2024, Apache-2.0 license
- **GitHub: KEMPtechnologies/terraform** -- Azure LoadMaster Terraform deployment module (HA + standalone)
- **GitHub: KEMPtechnologies/aws-cloudformation-templates** -- AWS CloudFormation for single instance and HA pair
- **GitHub: KEMPtechnologies/azure-resource-templates** -- ARM templates
- **GitHub: KEMPtechnologies/azure-quickstart-templates** -- Archived fork

---

## API Architecture

- **Type**: RESTful API over HTTPS
- **Default Port**: 443 (configurable, range 3-65530)
- **Two API Interfaces**: APIv1 (XML) and APIv2 (JSON)
- **Recommended Default**: **APIv2** for all post-licensing operations

### Recommended Approach: APIv2 First, APIv1 Fallback

Use **APIv2** (`/accessv2` JSON POST) as the default for all operations after licensing.
Fall back to **APIv1** (`/access/<cmd>?params`) only for:

1. **Pre-license operations** — EULA flow (`readeula`, `accepteula`, `accepteula2`) and
   licensing (`alsilicensetypes`, `alsilicense`, `set_initial_passwd`) may require APIv1
   as the appliance is not fully initialized
2. **Quick interactive debugging** — one-line curl commands for spot checks
3. **APIv2 failures** — if a specific command doesn't work on APIv2 (not observed to date)

**Rationale:**
- APIv2 has no character/URL-length limit — eliminates silent failures on long values
- JSON is easier to parse than XML in all common languages (bash/jq, Python, PowerShell)
- The STIG hardening script uses APIv2 exclusively for all post-license configuration
- Credentials in the body avoid HTTP Basic Auth header management
- Consistent interface — no per-call decision needed

### APIv2 (JSON) — Default

- **Endpoint**: `POST https://<LM_IP>:<PORT>/accessv2`
- **Request Format**: JSON body
- **Response Format**: JSON
- **Authentication**: Credentials in JSON body (`apiuser`/`apipass` or `apikey`)
- **Size Limit**: None — POST body has no practical limit

**Request structure:**
```json
{
  "apiuser": "bal",
  "apipass": "password",
  "cmd": "<command>",
  "param": "<parameter-name>",
  "value": "<parameter-value>"
}
```

Alternative with API key:
```json
{
  "apikey": "<api-key>",
  "cmd": "<command>",
  "param": "<parameter-name>",
  "value": "<parameter-value>"
}
```

**Success response:**
```json
{"code": 200, "message": "Command completed ok", "status": "ok"}
```

**Get response (returns parameter value directly):**
```json
{"code": 200, "hostname": "vlm14", "status": "ok"}
```

**Error response:**
```json
{"code": 422, "message": "Error description", "status": "fail"}
```

**APIv2 Response Format Differences (vs APIv1):**

APIv2 returns JSON with different type representations than APIv1 XML. Be aware when parsing:

| Parameter | APIv1 (XML) | APIv2 (JSON) |
|-----------|-------------|--------------|
| `nameserver` | `8.8.8.8,8.8.4.4` (string) | `["8.8.8.8","8.8.4.4"]` (array) |
| `sessioncontrol` | `yes` | `true` (boolean) |
| `enableapi` | `yes` | `true` (boolean) |
| `nonlocalrs` | `yes` | `true` (boolean) |
| `sslrenegotiate` | `no` | `false` or empty |
| `sessionbasicauth` | `no` | `false` or empty |
| `adminclientaccess` | `1` (string) | `1` (number) |

> **Note:** When checking boolean values from APIv2, test for both `true`/`false` and
> empty string. Some disabled params return empty rather than `false`.

**Common commands via APIv2:**
```bash
# Set a parameter
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"set","param":"hostname","value":"vlm14"}'

# Get a parameter
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"get","param":"hostname"}'

# Get all parameters
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"getall"}'

# List API commands
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"listapi"}'

# Add a virtual service
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"addvs","vs":"10.0.0.100","port":"443","prot":"tcp","template":"Exchange 2019 HTTPS re-encrypted"}'

# Add a real server to a sub-VS (use numeric index as "vs")
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"addrs","vs":"2","rs":"10.0.0.4","rsport":"443"}'

# Create cipher set
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"modifycipherset","name":"FIPS2","value":"ECDHE-RSA-AES256-GCM-SHA384:..."}'

# Disable GEO
curl -sk -X POST "https://$LM_IP/accessv2" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"disablegeo"}'
```

### APIv1 (Legacy — XML) — Fallback / Pre-License Only

- **Base URL Pattern**: `https://<LM_IP>:<PORT>/access/<command>?<params>`
- **Response Format**: XML
- **Authentication**: HTTP Basic Auth header
- **Size Limit**: ~2000-4000 characters (URL/query-string limit) — long values cause connection resets (HTTP 000)
- **Use for**: Pre-license flow, quick debugging, short-value operations

```xml
<Response>
  <stat>200</stat>
  <Success>
    <Data>...</Data>
  </Success>
</Response>
```

On error:
```xml
<Response>
  <stat>4xx</stat>
  <Error>Error description</Error>
</Response>
```

### API Interface Comparison

| Feature | APIv1 (`/access/`) | APIv2 (`/accessv2`) |
|---------|-------------------|---------------------|
| Method | GET (query-string) | POST (JSON body) |
| Response | XML | JSON |
| Auth | Basic Auth header | In JSON body |
| Size limit | ~2000-4000 chars | None |
| Pre-license | Works | May not be available |
| Post-license | Works (with limits) | **Recommended** |
| STIG script | Not used | Primary method |
| Value encoding | URL-encode required | JSON escaping |
| Parsing | XML (complex) | JSON (simple with jq) |

> **Live-validated (2026-06-16):** Setting `WUIPreauth` (~1800 chars HTML) via APIv1 caused
> HTTP 000 (connection reset). The same value set successfully via APIv2 JSON POST.
> The `SSHPreAuth` console banner (~500 chars) worked fine via APIv1.

### Lifecycle: Which API to Use When

| Phase | Interface | Reason |
|-------|-----------|--------|
| EULA acceptance | APIv1 | Appliance not fully initialized |
| License activation | APIv1 | Appliance not fully initialized |
| Set initial password | APIv1 | Appliance not fully initialized |
| Re-enable API (`enableapi`) | APIv2 | STIG script uses accessv2 for this |
| All post-license configuration | **APIv2** | No size limits, consistent, reliable |
| Template upload (`uploadtemplate`) | **APIv1** | Requires binary POST body (`--data-binary @file`) — not a JSON operation |
| Quick interactive checks | APIv1 | Convenience (one-liner curl) |

> **Live-validated (2026-06-16):** Full end-to-end run confirmed this lifecycle. APIv1 used
> for steps 1-6 (EULA through initial password). APIv2 used for all subsequent configuration
> including `addvs` with template names, `addrs` to sub-VS, `modifycipherset`, and long HTML
> banners. The only post-license APIv1 call was `uploadtemplate` (binary file upload).

- **Authentication**:
  - **Credentials**: Username/password (PSCredential object in PowerShell)
  - **Client Certificate**: SubjectCN + optional CertificateStoreLocation
  - Only one method at a time
- **User-Agent**: `KempLoadBalancerPowershellModule`
- **TLS**: 1.1 and 1.2 enforced; server certificate validation is bypassed by the SDK
- **File Uploads**: HTTP POST with `application/x-www-form-urlencoded` content type

### Return Object Structure (PowerShell SDK)

```
ReturnCode  : 200 (success) | 400/401/422 (error)
Response    : "Command successfully executed." or error message
Data        : PSObject with command-specific data
```

---

## Key API Patterns

### Virtual Service Identification
```
vs=<IP>&port=<port>&prot=<protocol>
```
Or by VSIndex.

### Real Server Identification (within a VS context)
```
rs=<IP>&rsport=<port>
```

### Generic Parameter Get/Set
```
GET  https://<LM>:<PORT>/access/get?param=<name>
SET  https://<LM>:<PORT>/access/set?param=<name>&value=<val>
```

### Parameter Name Mappings (SDK to API)

| SDK Parameter | API Parameter |
|---|---|
| VSIndex | vs |
| VirtualService | vs |
| Protocol | prot |
| VSPort | port |
| RSIndex | rs |
| RealServer | rs |
| RealServerPort | rsport |
| RuleName | rule |
| InterfaceID | iface |
| IPAddress | addr |
| HAMode | hamode |
| Partner | partner |
| ConnectTimeout | timeout |
| CurrentPassword | currpassword |
| NewPassword | password |
| Permissions | perms |
| ScalingOver64KConnections | localbind |
| AddPortToActiveCookie | addcookieport |
| RFCConform | rfcconform |
| CloseOnError | closeonerror |
| DropOnRSFail | droponfail |
| DropAtDrainEnd | dropatdrainend |
| L7AuthTimeoutSecs | authtimeout |
| L7ClientTokenTimeoutSecs | clienttokentimeout |
| L7ConnectionDrainTimeoutSecs | finalpersist |
| AllowEmptyPosts | allowemptyposts |
| ForceCompleteRSMatch | ForceFullRSMatch |
| SlowStart | slowstart |
| ShareSubVSPersistance | ShareSubVSPersist |
| SSHPreAuthBanner | SSHPreAuth |
| MultiHomedWui | multihomedwui |
| AllowUpdateChecks | tethering |

### Content Rule Types

| Type | Numeric Value |
|---|---|
| MatchContentRule | 0 |
| AddHeaderRule | 1 |
| DeleteHeaderRule | 2 |
| ReplaceHeaderRule | 3 |
| ModifyUrlRule | 4 |
| ReplaceBodyRule | 5 |

### GEO Selection Criteria

| Internal Name | Display Name |
|---|---|
| rr | RoundRobin |
| wrr | WeightedRoundRobin |
| fw | FixedWeighting |
| rsr | RealServerLoad |
| prx | Proximity |
| lb | LocationBased |
| all | AllAvailable |

---

## API Categories & Cmdlets

### 1. Connection & Session

| Cmdlet | Description |
|---|---|
| `Initialize-LmConnectionParameters` | Set session-level LM address, port, credentials |
| `Test-LmServerConnection` | Test connectivity to the LoadMaster |

### 2. EULA & Licensing

| Cmdlet | REST Command | Description |
|---|---|---|
| `Read-LicenseEULA` | `readeula` | Retrieve the EULA text and magic string |
| `Confirm-LicenseEULA` | `accepteula` | Accept EULA (mandatory before licensing) |
| `Confirm-LicenseEULA2` | `accepteula2` | Accept/decline telemetry EULA |
| `Request-LicenseOnline` | `license` | License via KEMP licensing server (requires KempId/Password) |
| `Request-LicenseOffline` | `license` | Offline license request |
| `Update-LicenseOnline` | | Update existing license online |
| `Update-LicenseOffline` | | Update existing license offline |
| `Request-LicenseOnPremise` | `alsilicense` | License via on-premises ASL server |
| `Get-LicenseAccessKey` | | Retrieve license access key |
| `Get-LicenseType` | | Get available license types |
| `Get-LicenseInfo` | | Get current license information |
| `Get-AslLicenseType` | | Get ASL license types |
| `Set-LicenseInitialPassword` | `set` | Set initial system password after licensing |

### 3. Virtual Services (ADC)

| Cmdlet | REST Command | Description |
|---|---|---|
| `New-AdcVirtualService` | `addvs` | Create a new virtual service |
| `Get-AdcVirtualService` | `showvs` | Get VS configuration (single or list) |
| `Set-AdcVirtualService` | `modvs` | Modify VS settings |
| `Remove-AdcVirtualService` | `delvs` | Delete a virtual service |
| `Set-AdcSubVirtualService` | `modvs` | Modify sub-virtual service settings |
| `Get-AdcVSTotals` | | Get VS totals/summary |

**Key VS Parameters**: VirtualService (IP), VSPort, VSProtocol (tcp/udp), VSIndex, NickName, Enable, Transparent, ServerInit, StartTLSMode, Idletime, Persist, PersistTimeout, Schedule, CheckType, CheckUrl, CheckPort, LdapEndpoint, ForceL4, ForceL7, MultiConnect, ClientCert, SecurityHeaderOptions, InterceptMode, Intercept, AlertThreshold, OwaspOpts, BlockingParanoia, IPDetectionMode, ExcludeDirectories, AddAuthHeader, SingleSignOnMessage, UserPwdExpiryWarn, UserPwdExpiryWarnDays, CaptchaPublicKey, CaptchaPrivateKey, CaptchaValidityPeriod, InputAuthMode, OutputAuthMode

### 4. Real Servers

| Cmdlet | REST Command | Description |
|---|---|---|
| `New-AdcRealServer` | `addrs` | Add a real server to a VS |
| `Get-AdcRealServer` | `showrs` | Get RS configuration |
| `Set-AdcRealServer` | `modrs` | Modify RS settings |
| `Remove-AdcRealServer` | `delrs` | Remove RS from VS |
| `Enable-AdcRealServer` | | Enable a real server |
| `Disable-AdcRealServer` | | Disable a real server |

**Key RS Parameters**: RealServer (IP), RealServerPort, Weight, Forward, Enable, Limit, Critical, Follow, AddToAllSubvs

### 5. Content Rules (L7)

| Cmdlet | REST Command | Description |
|---|---|---|
| `New-AdcContentRule` | `addrule` | Create content rule |
| `Get-AdcContentRule` | `showrule` | Get content rules |
| `Set-AdcContentRule` | `modrule` | Modify content rule |
| `Remove-AdcContentRule` | `delrule` | Delete content rule |

**Rule Types**: MatchContentRule, AddHeaderRule, DeleteHeaderRule, ReplaceHeaderRule, ModifyUrlRule, ReplaceBodyRule

**Key Parameters**: RuleName, Pattern, Replacement, Header, OnlyOnNoFlag

### 6. TLS / Certificates

| Cmdlet | REST Command | Description |
|---|---|---|
| `New-TlsCertificate` | `addcert` | Upload/install TLS certificate |
| `Get-TlsCertificate` | `readcert` | Retrieve certificate details |
| `Remove-TlsCertificate` | `delcert` | Remove a certificate |
| `New-TlsIntermediateCertificate` | | Add intermediate cert |
| `Get-TlsCipherSet` | | Get configured cipher set |
| `Set-TlsCipherSet` | | Set cipher suite configuration |
| `Backup-TlsCertificate` | | Backup all certificates |
| `Restore-TlsCertificate` | | Restore certificates from backup |

### 7. SSO Domains

| Cmdlet | REST Command | Description |
|---|---|---|
| `New-SSODomain` | `adddomain` | Create SSO domain |
| `Get-SSODomain` | `showdomain` | Get SSO domain config |
| `Set-SSODomain` | `moddomain` | Modify SSO domain |
| `Remove-SSODomain` | `deldomain` | Delete SSO domain |
| `Get-SSODomainLockedUser` | `showdomainlockedusers` | List locked users |
| `Set-SSODomainLockedUser` | `unlockdomainusers` | Unlock users |
| `Get-SSODomainSession` | | Get active SSO sessions |
| `Get-SSODomainQuerySession` | | Query SSO sessions |

**SSO Domain Parameters**: auth_type (SAML, LDAP, etc.), server_side, logon_fmt, logon_fmt2, logon_transcode, logon_domain, kerberos_domain, kerberos_kdc, kcd_username, max_failed_auths, reset_fail_tout, unblock_tout, sess_tout_idle_priv, sess_tout_duration_priv, cert_asi, cert_check_cn, radius_send_nas_id, radius_nas_id, ldapephc

### 8. LDAP Endpoints

| Cmdlet | Description |
|---|---|
| `New-LdapEndpoint` | Create LDAP endpoint |
| `Get-LdapEndpoint` | Get LDAP endpoint config |
| `Set-LdapEndpoint` | Modify LDAP endpoint |
| `Remove-LdapEndpoint` | Delete LDAP endpoint |

**Parameters**: LdapProtocol, ReferralCount, server, Timeout

### 9. GEO Load Balancing (GSLB)

| Cmdlet | Description |
|---|---|
| `New-GeoFQDN` | Create GEO FQDN |
| `Get-GeoFQDN` | Get GEO FQDN configuration |
| `Set-GeoFQDN` | Modify GEO FQDN |
| `Remove-GeoFQDN` | Delete GEO FQDN |
| `New-GeoCluster` | Create GEO cluster |
| `Get-GeoCluster` | Get GEO cluster config |
| `Set-GeoCluster` | Modify GEO cluster |
| `Remove-GeoCluster` | Delete GEO cluster |
| `Set-GeoFQDNSiteAddress` | Set site address mapping |
| `Set-GeoFQDNSiteMapping` | Set site mapping (with MappingPort and MappingName) |
| `Get-GeoCustomLocation` | Get custom locations |
| `Set-GeoCustomLocation` | Set custom location |
| `Remove-GeoCustomLocation` | Delete custom location |
| `Get-GeoIPRange` | Get IP range configuration |
| `Set-GeoIPRange` | Set IP range |
| `Remove-GeoIPRange` | Delete IP range |
| `Get-GeoPartnerStatus` | Get GEO partner status |
| `Get-GeoIPBlacklistDatabaseConfiguration` | Get blocklist DB config |
| `Get-GeoIPBlocklistDatabaseConfiguration` | Get blocklist DB config (alias) |
| `Set-GeoIPBlacklistDatabaseConfiguration` | Set blocklist DB config |
| `Get-GeoIPWhitelist` | Get allowlist |
| `Get-GeoIPAllowlist` | Get allowlist (alias) |
| `Export-GeoIPWhitelistDatabase` | Export allowlist to file |
| `Export-GeoIPAllowlistDatabase` | Export allowlist (alias) |
| `Get-GeoDNSSECConfiguration` | Get DNSSEC config |
| `Set-GeoDNSSECConfiguration` | Set DNSSEC config |
| `Get-GeoLmMiscParameter` | Get misc GEO parameters (SOA, zone, nameserver, email) |
| `Set-GeoLmMiscParameter` | Set misc GEO parameters |
| `Get-GeoStatistics` | Get GEO statistics |
| `Test-LmGeoEnabled` | Check if GEO is enabled |

**FQDN Fields**: Fqdn, Failover, PublicRequest, PrivateRequest, SiteFailureDelay, SelectionCriteria

### 10. WAF (Web Application Firewall)

| Cmdlet | Description |
|---|---|
| `Get-WafRules` | List WAF rules |
| `Install-WafRulesDatabase` | Install WAF rules DB |
| `Update-WafRulesDatabase` | Update WAF rules DB |
| `Get-WafRulesAutoUpdateConfiguration` | Get auto-update config |
| `Set-WafRulesAutoUpdateConfiguration` | Set auto-update config |
| `Get-WafAuditFiles` | Get WAF audit files |
| `Export-LmWafTempRemoteLog` | Export WAF temp remote log |
| `Reset-LmWafTempRemoteLog` | Reset WAF temp remote log |
| `Get-WafCustomRuleData` | Get custom rule data |
| `Set-WafCustomRuleData` | Set custom rule data |
| `Get-WafCustomRuleSet` | Get custom rule sets |
| `New-WafCustomRuleSet` | Create custom rule set |
| `Remove-WafCustomRuleSet` | Delete custom rule set |
| `Get-WafChangeLog` | Get WAF change log |

### 11. Networking

| Cmdlet | Description |
|---|---|
| `Get-NetworkInterface` | Get network interface configuration |
| `Set-NetworkInterface` | Set network interface parameters |
| `Get-LmNetworkInterface` | Get LoadMaster network interface details |
| `New-NetworkRoute` | Create static route |
| `Get-NetworkRoute` | Get route table |
| `Remove-NetworkRoute` | Delete route |
| `Test-LmNetworkRoute` | Traceroute |
| `Add-NetworkVLAN` | Add VLAN to interface |
| `Remove-NetworkVLAN` | Remove VLAN |
| `Add-NetworkVxLAN` | Add VxLAN to interface |
| `Remove-NetworkVxLAN` | Remove VxLAN |
| `Add-BondedInterface` | Create bonded interface |
| `Remove-BondedInterface` | Remove bonded interface |
| `Get-LmDnsConfiguration` | Get DNS settings |
| `Set-LmDnsConfiguration` | Set DNS settings |

**DNS / Nameserver Notes:**
- Parameter name: `nameserver` (the old `namserver` typo variant is deprecated)
- Multiple nameservers use a **single comma-separated value**: `8.8.8.8,8.8.4.4`
- There is no `namesecondary` parameter — returns `Unknown parameter value`
- Setting to empty string deletes all name servers (blocked if `dnssecclient` is enabled)
- REST API: `access/set?param=nameserver&value=8.8.8.8,8.8.4.4`
| `Get-LmSnmpConfiguration` | Get SNMP settings |
| `Set-LmSnmpConfiguration` | Set SNMP settings |
| `Get-HostsEntry` | Get /etc/hosts entries |
| `New-HostsEntry` | Add hosts entry |
| `Remove-HostsEntry` | Remove hosts entry |

### 12. Packet Filter / ACL

| Cmdlet | Description |
|---|---|
| `Get-VSPacketFilterACL` | Get VS-level ACL (black/white/allow/block list) |
| `New-VSPacketFilterACL` | Add VS ACL entry |
| `Remove-VSPacketFilterACL` | Remove VS ACL entry |
| `Get-GlobalPacketFilterACL` | Get global ACL |
| `New-GlobalPacketFilterACL` | Add global ACL entry |
| `Remove-GlobalPacketFilterACL` | Remove global ACL entry |
| `Get-PacketFilterOption` | Get filter options (isenabled, isdrop, isifblock, iswuiblock, wuiaddr) |
| `Set-PacketFilterOption` | Set filter options |

### 13. High Availability (HA)

| Cmdlet | Description |
|---|---|
| `Get-LmHAMode` | Get HA mode |
| `Set-LmHAMode` | Set HA mode (single, master, slave) |
| `Get-AzureHAConfiguration` | Get Azure HA config |
| `Set-AzureHAConfiguration` | Set Azure HA config |
| `Get-AwsHAConfiguration` | Get AWS HA config |
| `Set-AwsHAConfiguration` | Set AWS HA config |
| `Get-LmCloudHaConfiguration` | Get generic cloud HA config |

**HA Parameters**: HAMode, Partner, Hcp, HealthCheckPort, Hapreferred, HealthCheckAllInterfaces

### 14. Backup & Restore

| Cmdlet | Description |
|---|---|
| `Backup-LmConfiguration` | Backup LoadMaster config to local file |
| `Restore-LmConfiguration` | Restore config from backup file |
| `Get-LmBackupConfiguration` | Get backup schedule config |
| `Set-LmBackupConfiguration` | Set backup schedule (backupmethod parameter) |

### 15. Templates

| Cmdlet | Description |
|---|---|
| `Install-Template` | Import VS template |
| `Get-Template` | List available templates |
| `Export-VirtualServiceTemplate` | Export VS config as template |

**Template Workflow (Live Validated 2026-06-16):**
1. Upload template: `POST /access/uploadtemplate` with `--data-binary @file.tmpl`
2. Create VS from template: `GET /access/addvs?vs=<IP>&port=<port>&prot=tcp&template=<name>`
3. Template names must be URL-encoded (spaces → `%20`)
4. A single `.tmpl` file can contain multiple templates

**Sub-VS / Content Switching Notes:**
- Templates like "Exchange 2019 HTTPS re-encrypted" create a Master VS with multiple sub-VS
- Master VS has `<MasterVS>N</MasterVS>` where N = number of sub-VS
- Sub-VS appear in `listvs` with `<VSPort>0</VSPort>` and `<MasterVSID>N</MasterVSID>`
- To add RS to a sub-VS, use `vs=<VSIndex>` (numeric index, NOT an IP address)
- Adding RS directly to a Master VS returns "Couldn't create RS"
- The `vs_index` parameter does NOT work for sub-VS addressing — use `vs=<index>` instead

### 16. Statistics & Logging

| Cmdlet | Description |
|---|---|
| `Get-LogStatistics` | Get VS/RS/CPU/Memory/Network/TPS/DiskUsage stats |
| `Get-LmSyslogFile` | List syslog files |
| `Export-LmSyslogFile` | Download syslog file |
| `Reset-LmSyslogFile` | Reset syslog files |
| `Get-LmExtendedLogFile` | List extended log files |
| `Export-LmExtendedLogFile` | Download extended log file |
| `Reset-LmExtendedLogFile` | Reset extended log files |
| `Get-LogSyslogConfiguration` | Get syslog configuration |
| `Set-LogSyslogConfiguration` | Set syslog configuration |
| `Get-EspExtendedLogConfiguration` | Get ESP extended log config |
| `Set-EspExtendedLogConfiguration` | Set ESP extended log config |

**Statistics Data**: Vs (per-VS stats), Rs (per-RS stats), VStotals, CPU, Network, Memory, DiskUsage, TPS, ClientLimits, CountryCounts, ChangeTime

### 17. Security & Users

| Cmdlet | Description |
|---|---|
| `New-SecUser` | Create local admin user |
| `Get-SecUser` | Get user details |
| `Set-SecUserPermission` | Set user permissions |
| `Remove-SecUser` | Delete user |
| `Set-SecUserPassword` | Change user password |
| `New-SecRemoteUserGroup` | Create remote user group |
| `Get-SecRemoteUserGroup` | Get remote user groups |
| `Set-SecRemoteUserGroup` | Modify remote user group |
| `Remove-SecRemoteUserGroup` | Delete remote user group |
| `New-ApiSecurityKey` | Generate API key |
| `Get-ApiSecurityKeys` | List API keys |
| `Remove-ApiSecurityKey` | Revoke API key |
| `Get-SecAdminWuiConfiguration` | Get WUI security config |
| `Set-SecAdminWuiConfiguration` | Set WUI security config (WUITLSProtocols, login method, cert mapping) |

**Login Methods**: PasswordOnly (0), PasswordOrClientCertificate (1), ClientCertificateRequired (2), ClientCertificateRequiredOCSP (3)

**WUI Cert Mapping**: UserPrincipalName (0), Subject (1), IssuerandSubject (2), IssuerandSerialNumber (3)

### 18. SDN Controllers

| Cmdlet | Description |
|---|---|
| `Add-SdnController` | Add SDN controller |
| `Get-SdnController` | Get SDN controller(s) |
| `Set-SdnController` | Modify SDN controller |
| `Remove-SdnController` | Remove SDN controller |

### 19. VPN (IPsec)

| Cmdlet | Description |
|---|---|
| `Get-LmVpnIkeDaemonStatus` | Get IKE daemon status |
| `New-LmVpnConnection` | Create VPN connection |
| `Get-LmVpnConnection` | Get VPN connection config |
| `Set-LmVpnConnection` | Modify VPN connection |
| `Remove-LmVpnConnection` | Delete VPN connection |

**VPN Data**: defaultLocalIP, defaultLocalSubnets, defaultLocalID, status

### 20. SAML

| Cmdlet | Description |
|---|---|
| `Set-SAMLSPEntity` | Set SAML Service Provider entity config |
| `New-SAMLIdPMetadata` | Upload IdP metadata |
| `Export-SAMLCertificate` | Export SAML certificate |

**Parameters**: idp_match_cert

### 21. ACME / Let's Encrypt

| Cmdlet | Description |
|---|---|
| `Register-LEAccount` | Register ACME account |
| `Request-LECertificate` | Request new certificate |
| `Renew-LECertificate` | Renew existing certificate |
| `Remove-LECertificate` | Remove LE certificate |
| `Get-LECertificate` | List LE certificates |
| `Get-LEAccountInfo` | Get ACME account info |
| `Set-LEDirectoryURL` | Set ACME directory URL |
| `Set-LERenewPeriod` | Set auto-renew period |
| `Set-LEKID` | Set Key ID |
| `Set-LEHMAC` | Set HMAC key |

**ACME Commands (7.2.61+):** The Let's Encrypt commands above were renamed to generic ACME
commands that support both Let's Encrypt and DigiCert. The new REST commands are:
`registeracmeaccount`, `acmeaccountinfo`, `addacmecert`, `renewacmecert`, `delacmecert`,
`listacmecert`, `getacmecert`, `getacmedirectoryurl`, `setacmedirectoryurl`,
`getacmerenewperiod`, `setacmerenewperiod`, `setacmekid`, `setacmehmac`, `delacmeconfig`.
All accept an `acmetype` parameter: `1` = Let's Encrypt, `2` = DigiCert.

### 21b. Kubernetes Ingress Controller (7.2.61+)

| REST Command | Description |
|---|---|
| `addlmingressk8sconf` | Upload Kube config file (POST binary) |
| `dellmingressk8sconf` | Delete Kube config file |
| `showlmingressk8sconf` | List contexts in Kube config |
| `getlmingressmode` | Get ingress operations mode |
| `setlmingressmode` | Set operations mode (Ingress/Gateway) |
| `getlmingressnamespace` | Get watched namespace |
| `setlmingressnamespace` | Set namespace to watch |
| `getlmingresswatchtimeout` | Get watch timeout (seconds) |
| `setlmingresswatchtimeout` | Set watch timeout |
| `restartlmingress` | Restart the ingress controller |

### 21c. Additional Commands (7.2.61+)

| REST Command | Category | Description |
|---|---|---|
| `dupvs` | Virtual Services | Duplicate a VS or sub-VS |
| `owasprules` | WAF | List/enable/disable/filter OWASP rules per VS |
| `showlocalreservedports` | System | Show reserved local ports |
| `setlocalreservedports` | System | Set reserved local ports |

### 22. System Maintenance

| Cmdlet | Description |
|---|---|
| `Restart-Lm` | Reboot LoadMaster |
| `Shutdown-Lm` | Shutdown LoadMaster |
| `Install-LmPatch` | Install firmware patch |
| `Uninstall-LmPatch` | Rollback firmware patch |
| `Get-LmPreviousFirmwareVersion` | Get previous firmware version |
| `Install-LmAddon` | Install add-on package |
| `Get-LmAddOn` | List installed add-ons |
| `Remove-LmAddOn` | Remove add-on |
| `Get-LmDateTimeConfiguration` | Get date/time settings |
| `Set-LmDateTimeConfiguration` | Set date/time settings |

### 23. Diagnostics

| Cmdlet | Description |
|---|---|
| `Get-LmDebugInformation` | Get debug info (slabinfo, etc.) |
| `Test-LmNetworkRoute` | Traceroute to target |
| `Ping-Host` | Ping from LoadMaster |
| `Get-TcpDumpData` | Capture TCP dump |
| `Get-LmProcessInfo` | Get process information |

### 24. Generic Parameters

| Cmdlet | Description |
|---|---|
| `Get-LmParameter` | Get any single LM parameter by name |
| `Set-LmParameter` | Set any single LM parameter |
| `Get-LmAllParameters` | Get all LM parameters at once |
| `Get-LmApiList` | Get list of all API commands and version |

### 25. Client Limits & Rate Limiting

| Cmdlet | Description |
|---|---|
| `Get-AdcLimitRules` | Get limit rules |
| `Get-ClientCPSLimit` | Get connections-per-second limit |
| `Set-ClientCPSLimit` | Set CPS limit |
| `Get-ClientRPSLimit` | Get requests-per-second limit |
| `Set-ClientRPSLimit` | Set RPS limit |
| `Get-ClientMaxcLimit` | Get max connections limit |
| `Set-ClientMaxcLimit` | Set max connections limit |
| `Get-ClientBandwidthLimit` | Get bandwidth limit |
| `Set-ClientBandwidthLimit` | Set bandwidth limit |
| `Get-LmIPConnectionLimit` | Get IP connection limits |
| `Set-LmIPConnectionLimit` | Set IP connection limits |

### 26. Cluster (N+M)

| Cmdlet | Description |
|---|---|
| `New-Cluster` | Create cluster |
| `Get-ClusterStatus` | Get cluster status |

### 27. Telemetry (Exporter)

| Cmdlet | Description |
|---|---|
| `Get-LmTelemetryStatus` | Get telemetry status |
| `Enable-LmTelemetry` | Enable telemetry |

### 28. Strongswan VPN (Route-based)

| Cmdlet | Description |
|---|---|
| `New-LmStrongswanVpnConnection` | Create route-based VPN |
| `Get-LmStrongswanVpnConnection` | Get VPN config |
| `Set-LmStrongswanVpnConnection` | Modify VPN |
| `Remove-LmStrongswanVpnConnection` | Delete VPN |

### 29. AFE (Application Firewall Engine)

| Cmdlet | Description |
|---|---|
| `Get-AfeConfiguration` | Get AFE config |
| `Set-AfeConfiguration` | Set AFE config |
| `Update-AfeIDSRules` | Update IDS rules |

---

## Cloud Deployment Details

### Azure

- **Marketplace Image**: `kemptech:vlm-azure:basic-byol`
- **Publisher**: `kemptech`
- **Offer**: `vlm-azure`
- **SKU**: `basic-byol`
- **OS**: Linux
- **Recommended VM Size**: `Standard_DS2_v2`
- **WUI Port**: 8443
- **Health Probe Port**: 8444
- **SSH Port**: 22
- **Default Admin User**: `bal`
- **HA Deployment**: Availability Set + Azure Load Balancer with NAT rules (port 8441 -> 8443 for LM0, 8442 -> 8443 for LM1)
- **Terraform Module**: `github.com/KEMPtechnologies/terraform.git//azure//loadmaster`

### AWS

- **Deployment**: CloudFormation BYOL template
- **Single Instance**: `KEMP-LoadMaster-Basic-Deploy-AWS` -- deploys into existing VPC/Subnet
- **HA Pair**: `KEMP-LoadMaster-HA-Pair-AWS` -- deploys into 2 subnets across 2 AZs with AWS ELB

---

## Setup Workflow (from examples)

```powershell
# 1. Create credentials
$creds = New-Object System.Management.Automation.PSCredential("bal", $securePassword)

# 2. Read and accept EULA
$reula = Read-LicenseEULA -LoadBalancer $LMIP -Credential $creds
$ceula = Confirm-LicenseEULA -Magic $reula.Data.Eula.MagicString -LoadBalancer $LMIP -Credential $creds
$ceula2 = Confirm-LicenseEULA2 -Magic $ceula.Data.Eula2.MagicString -Accept "yes" -LoadBalancer $LMIP -Credential $creds

# 3. License the machine
$lic = Request-LicenseOnline -LoadBalancer $LMIP -Credential $creds -KempId $KEMPID -Password $KEMPPASSWD

# 4. Set initial password
$setp = Set-LicenseInitialPassword -Passwd $securePassword -LoadBalancer $LMIP -Credential $creds

# 5. Re-enable API interface (required after licensing)
Set-LmParameter -Param "enableapi" -Value 1 -LoadBalancer $LMIP -Credential $creds

# 6. Set management interface IP (optional)
Set-NetworkInterface -InterfaceID 0 -Address "10.0.0.14/24" -LoadBalancer $LMIP -Credential $creds

# 7. Create virtual service
$vs = New-AdcVirtualService -VirtualService $VSIP -VSPort $VSPORT -VSProtocol $VSPROTOCOL -LoadBalancer $LMIP -Credential $creds

# 8. Add real server
$rs = New-AdcRealServer -VirtualService $VSIP -VSPort $VSPORT -VSProtocol $VSPROTOCOL -RealServer $RSIP -RealServerPort $RSPORT -LoadBalancer $LMIP -Credential $creds
```

### Setup Workflow (curl / REST API)

The following shows the equivalent workflow using direct REST API calls:

```bash
# 1. Read EULA (returns Magic token)
MAGIC=$(curl -sk "https://$LM_IP/access/readeula" | grep -oP '(?<=<Magic>).*?(?=</Magic>)')

# 2. Accept EULA (type: free, trial, or perm)
MAGIC2=$(curl -sk "https://$LM_IP/access/accepteula?magic=$MAGIC&type=free" \
  | grep -oP '(?<=<Magic>).*?(?=</Magic>)')

# 3. Accept telemetry EULA
curl -sk "https://$LM_IP/access/accepteula2?magic=$MAGIC2&accept=yes"

# 4. Get available license types
curl -sk "https://$LM_IP/access/alsilicensetypes?kempid=$KEMP_ID&password=$ENCODED_PASS"

# 5. Install license (use lic_type_id from step 4)
curl -sk "https://$LM_IP/access/alsilicense?kempid=$KEMP_ID&password=$ENCODED_PASS&lic_type_id=$LIC_ID"

# 6. Set initial password (retry — appliance needs ~5-25s after licensing)
sleep 5
curl -sk "https://$LM_IP/access/set_initial_passwd?passwd=$NEW_PASS"

# 7. Re-enable API interface (required after licensing)
curl -sk -u "bal:$NEW_PASS" "https://$LM_IP/access/set?param=enableapi&value=1"

# 8. Set management interface IP (optional, uses CIDR notation)
curl -sk -u "bal:$NEW_PASS" "https://$LM_IP/access/modiface?iface=0&addr=10.0.0.14/24"
# NOTE: After this call, the appliance responds on the new IP address
```

### Post-Licensing Required Steps

After `alsilicense` completes and the initial password is set, the following step is
**mandatory** before the API can be used for further configuration:

| Step | Command | Notes |
|------|---------|-------|
| Re-enable API | `access/set?param=enableapi&value=1` | API is disabled after licensing; must be re-enabled. Use `bal` + password (basic auth), not API key. |

### Management Interface Configuration

The management interface (eth0, interface ID `0`) IP can be changed using `access/modiface`:

- **Parameter**: `iface` (integer) — interface ID (`0` = eth0)
- **Parameter**: `addr` (string) — IP address in **CIDR notation** (e.g., `10.0.0.14/24`)
- **Important**: After changing the management IP, all subsequent API calls must use the new address
- **Response**: `<Success>Address changed</Success>`

Common interface configuration patterns:
```bash
# View current interface config
curl -sk -u "bal:PASS" "https://$LM_IP/access/showiface?iface=0"

# Change management IP
curl -sk -u "bal:PASS" "https://$LM_IP/access/modiface?iface=0&addr=10.0.0.14/24"

# Verify from new IP
curl -sk -u "bal:PASS" "https://10.0.0.14/access/showiface?iface=0"
```

---

## STIG Hardening (US Government Security)

The following parameters are set by the STIG hardening script (v3.20230906) to comply with
U.S. Government STIGs/SRGs. All validated on firmware 7.2.54.x (2026-06-16).

> **API Interface:** The STIG PowerShell script uses **APIv2** (`/accessv2` with JSON POST body)
> for all post-license operations. This is the recommended approach — it avoids the APIv1
> character limit that causes failures when setting long HTML warning banners. The examples
> below show APIv1 syntax for brevity, but production automation should use APIv2:
> ```bash
> curl -sk -X POST "https://$LM_IP/accessv2" \
>   -d '{"apiuser":"bal","apipass":"PASS","cmd":"set","param":"<name>","value":"<value>"}'
> ```

### Session & Authentication Hardening
```bash
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=sessioncontrol&value=yes"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=sessionbasicauth&value=0"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=sessionidletime&value=600"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=sessionmaxfailattempts&value=5"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=sessionconcurrent&value=3"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=adminclientaccess&value=1"
```

### TLS / Cipher Hardening
```bash
# Create FIPS2 cipher set (removes 3DES, SHA1, DH<2048 from FIPS set)
FIPS2="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:AES128-GCM-SHA256:AES128-SHA256"
curl -sk -u "bal:PASS" "https://$LM_IP/access/modifycipherset?name=FIPS2&value=$FIPS2"

# Assign to WUI and outbound
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=WUICipherset&value=FIPS2"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=OutboundCipherset&value=FIPS2"

# Restrict WUI to TLS 1.2+ and set TLS 1.3 ciphers
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=WUITLSProtocols&value=7"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=WUITLS13Ciphersets&value=TLS_AES_256_GCM_SHA384%20TLS_AES_128_GCM_SHA256"

# Disable SSL renegotiation
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=sslrenegotiate&value=0"
```

### Network & Service Hardening
```bash
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=nonlocalrs&value=yes"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=subnetorigin&value=yes"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=multigw&value=1"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=admingw&value=10.0.0.1"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=KcdCipherSha1&value=yes"
curl -sk -u "bal:PASS" "https://$LM_IP/access/set?param=CEFMsgFormat&value=yes"
curl -sk -u "bal:PASS" "https://$LM_IP/access/disablegeo"
```

### Warning Banners
```bash
# Console (SSH) banner — set via access/set?param=SSHPreAuth
# WUI banner — set via access/set?param=WUIPreauth (use accessv2 JSON endpoint for long HTML values)
# Note: Long banner HTML exceeds URL length limits; use POST to /accessv2 with JSON body:
curl -sk -X POST "https://$LM_IP/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASS","cmd":"set","param":"WUIPreauth","value":"<html>...</html>"}'
```

### Known STIG Exceptions
| Setting | Exception | Reason |
|---------|-----------|--------|
| Tethering | Cannot disable | Free/MELA/Pooled/SPLA licenses require mandatory tethering |
| FIPS2 cipher set | Not needed on LMOS 7.2.59+ | FIPS set already excludes weak algorithms |
| FIPS2 cipher set | Not applicable in SW FIPS Mode | Appliance manages its own cipher constraints |

### WUITLSProtocols Values
| Value | Protocols Enabled |
|-------|-------------------|
| 0 | All (TLS 1.0 + 1.1 + 1.2 + 1.3) |
| 3 | TLS 1.1 + 1.2 |
| 7 | TLS 1.2 + 1.3 (STIG recommended) |

---

## Changelog Highlights

- **2024-03-28**: Latest module update (v22392)
- **2020-02-07**: ACL on WUI access (v7.2.50+), SingleSignOnMessage parameter
- **2019-12-18**: Captcha parameters for VS
- **2019-11-12**: OnlyOnNoFlag for content rules
- **2019-10-10**: UserPwdExpiryWarn parameters, SSODomainQuerySession
- **2019-07-17**: WAF temp remote log export/reset
- **2019-04-23**: GEO statistics, GEO API fixes, LDAP timeout parameter, Remove-SplaInstance
- **2019-02-04**: DiskUsage in statistics, Read-LicenseEULA fix
- **2019-01-10**: Backup config updates, extended/syslog file management, ESP extended log, RADIUS params, WUI TLS protocol range update
- **2018-10-04**: ASL host parameter, ExcludeDirectories, AddAuthHeader, AddToAllSubvs, idp_match_cert

---

## Known Issues (from GitHub)

1. **AzureRM Conflicts** (#1): Generic function names like `Get-NetworkInterface` conflict with Azure PowerShell modules
2. **Wildcard Exports** (#2): Module manifest exports `*` instead of explicit function list
3. **Function Naming** (#3): Functions should be prefixed with `Kemp` to avoid conflicts
4. **Certificate Auth** (#4): Certificate-based auth may still prompt for credentials in some scenarios
5. **VS Code** (#6): Cannot load module in Visual Studio Code PowerShell terminal

---

## Preferred HA Modes

| Value | Description |
|---|---|
| 0 | No Preferred Host |
| 1 | Prefer First HA |
| 2 | Prefer Second HA |

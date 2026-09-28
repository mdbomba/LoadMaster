# access/restore

**Category**: system  
**Firmware tested**: 7.2.54.12.22642.RELEASE  
**PS Cmdlet**: `Restore-LmConfiguration`

## Description

Restores selected configuration sections from a LoadMaster backup.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `type` | integer | Yes | Restore scope from 1 through 15 |
| `data` | base64 string | APIv2 only | Base64-encoded backup file bytes |

| Type | Configuration restored |
|------|------------------------|
| `1` | Base |
| `2` | Virtual Service |
| `3` | Base and Virtual Service |
| `4` | GEO |
| `5` | Base and GEO |
| `6` | Virtual Service and GEO |
| `7` | Base, Virtual Service, and GEO |
| `8` | ESP SSO |
| `9` | ESP SSO and base |
| `10` | ESP SSO and Virtual Service |
| `11` | ESP SSO, Virtual Service, and base |
| `12` | ESP SSO and GEO |
| `13` | ESP SSO, GEO, and base |
| `14` | ESP SSO, GEO, and Virtual Service |
| `15` | ESP SSO, GEO, Virtual Service, and base |

## APIv1 Endpoint

```text
POST https://<host>:<port>/access/restore?type=<1-15>
```

Send the original backup file bytes as the request body:

```bash
curl -sk -u "bal:PASSWORD" -X POST \
  --data-binary "@LoadMaster-backup" \
  "https://10.0.0.69:443/access/restore?type=15"
```

APIv1 returns an XML success or error response.

## APIv2 Request

```bash
curl -sk -X POST "https://10.0.0.69:443/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"restore","type":15,"data":"<base64-encoded backup>"}'
```

## Notes

- Restore changes appliance configuration. Select the scope explicitly.
- `Path` is a local PowerShell option, not a REST parameter.

## See Also

- `access/backup` - downloads a configuration backup
- `access/restorecert` - restores a certificate backup

# access/backupcert

**Category**: certificates  
**Firmware tested**: 7.2.54.12.22642.RELEASE  
**PS Cmdlet**: `Backup-TlsCertificate`

## Description

Downloads an encrypted backup of all certificates from the appliance.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `password` | string | Yes | Case-sensitive, 7-64 ASCII alphanumeric characters |

## APIv1 Endpoint

```text
GET https://<host>:<port>/access/backupcert?password=<password>
```

```bash
curl -sk -u "bal:PASSWORD" \
  "https://10.0.0.69:443/access/backupcert?password=SecretPass1" \
  -o LoadMaster-certificates
```

On success, APIv1 returns the backup as `application/octet-stream`. API errors
are returned as XML. PowerShell's `Path` and `Force` options are local client
options, not REST parameters.

## APIv2 Request

```bash
curl -sk -X POST "https://10.0.0.69:443/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"backupcert","password":"SecretPass1"}'
```

APIv2 returns the backup as base64 in the JSON `data` field.

## See Also

- `access/restorecert` - restores a certificate backup
- `access/backup` - backs up LoadMaster configuration

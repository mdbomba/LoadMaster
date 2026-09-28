# access/restorecert

**Category**: certificates  
**Firmware tested**: 7.2.54.12.22642.RELEASE  
**PS Cmdlet**: `Restore-TlsCertificate`

## Description

Restores certificates from an encrypted certificate backup.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `password` | string | Yes | Passphrase used to create the backup; 7-64 ASCII alphanumeric characters |
| `type` | string | Yes | `full`, `third`, or `vs` (case-sensitive) |
| `data` | base64 string | APIv2 only | Base64-encoded certificate backup bytes |

`full` restores Virtual Service and intermediate certificates, `third` restores
intermediate certificates only, and `vs` restores Virtual Service certificates
only.

## APIv1 Endpoint

```text
POST https://<host>:<port>/access/restorecert?password=<password>&type=<type>
```

```bash
curl -sk -u "bal:PASSWORD" -X POST \
  --data-binary "@LoadMaster-certificates" \
  "https://10.0.0.69:443/access/restorecert?password=SecretPass1&type=full"
```

## APIv2 Request

```bash
curl -sk -X POST "https://10.0.0.69:443/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"restorecert","password":"SecretPass1","type":"full","data":"<base64-encoded backup>"}'
```

## Notes

- Restore changes the appliance certificate store. Select the scope explicitly.
- A 60-second or longer client timeout is recommended.

## See Also

- `access/backupcert` - creates a certificate backup
- `access/addcert` - uploads one certificate file

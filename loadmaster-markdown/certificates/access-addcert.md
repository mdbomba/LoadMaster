# access/addcert

**Category**: certificates  
**Firmware tested**: 7.2.54.12.22642.RELEASE  
**PS Cmdlet**: `New-TlsCertificate`

## Description

Uploads a certificate file to the LoadMaster certificate store. When uploading
a certificate and private key, place both in the same input file.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `cert` | string | Yes | Name used to identify the certificate on LoadMaster |
| `password` | string | No | Passphrase protecting the uploaded certificate file |
| `replace` | boolean | No | Replace a certificate with the same name |
| `data` | base64 string | APIv2 only | Base64-encoded certificate file bytes |

## APIv1 Endpoint

```text
POST https://<host>:<port>/access/addcert?cert=<name>&password=<password>&replace=<0-or-1>
```

Send the certificate file bytes as the request body:

```bash
curl -sk -u "bal:PASSWORD" -X POST \
  --data-binary "@server-cert.pem" \
  "https://10.0.0.69:443/access/addcert?cert=example-name&replace=0"
```

## APIv2 Request

```bash
curl -sk -X POST "https://10.0.0.69:443/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"addcert","cert":"example-name","replace":false,"data":"<base64-encoded certificate file>"}'
```

## Notes

- APIv1 returns XML. APIv2 returns JSON.
- A 60-second or longer client timeout is recommended for certificate operations.
- `Path` is a local PowerShell option, not a REST parameter.

## See Also

- `access/delcert` - removes a certificate
- `access/listcert` - lists stored certificates

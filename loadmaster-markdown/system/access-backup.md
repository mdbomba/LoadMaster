# access/backup

**Category**: system  
**Firmware tested**: 7.2.54.12.22642.RELEASE  
**PS Cmdlet**: `Backup-LmConfiguration`

## Description

Downloads a LoadMaster configuration backup bundle from the appliance.

## APIv1 Endpoint

```text
GET https://<host>:<port>/access/backup
```

The command has no backup-specific request parameters. The `Path` and `Force`
options exposed by the PowerShell cmdlet control the local output file and are
not REST parameters.

```bash
curl -sk -u "bal:PASSWORD" "https://10.0.0.69:443/access/backup" \
  -o LoadMaster-backup
```

On success, APIv1 returns `application/octet-stream` with the backup bytes. Use
the client output option, such as curl's `-o`, to choose a local filename. API
errors are returned as XML.

## APIv2 Request

```bash
curl -sk -X POST "https://10.0.0.69:443/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"backup"}'
```

APIv2 returns the backup as base64 in the JSON `data` field:

```json
{"code":200,"data":"<base64-encoded backup>","status":"ok"}
```

## Notes

- This operation reads configuration and does not change appliance state.
- `backupcert` creates a separate certificate backup.

## See Also

- `access/restore` - restores a configuration backup
- `access/backupcert` - backs up certificates separately

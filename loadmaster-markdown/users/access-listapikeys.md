# access/listapikeys

**Category**: users  
**Firmware tested**: 7.2.54.12.22642.RELEASE  
**PS Cmdlet**: `Get-SecApiKey`

## Description

Retrieves sec API key.

## Endpoint

```text
GET https://<host>:<port>/access/listapikeys?apikey=<apikey>
```

## HTTP Method

`GET` — read/query operation.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `apikey` | string | Yes | API key used instead of basic-auth credentials. |

## Example Request

```bash
curl -sk -u "bal:PASSWORD" "https://LOADMASTER_HOST:443/access/listapikeys?apikey=YOUR_API_KEY"
```

## Example Response (XML)

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<Response stat="200" code="ok">
  <Success>
    <Data>
      <!-- listapikeys fields -->
    </Data>
  </Success>
</Response>
```


## Example Request (APIv2)

```bash
curl -sk -X POST "https://10.0.0.69:443/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"listapikeys","apikey":"example"}'
```

## Notes

- API v1 responses are XML. Do not expect JSON payloads from the main response body.
- This is a safe read/query operation and does not modify appliance state.

## See Also

- `access/addapikey` — creates sec API key
- `access/delapikey` — removes sec API key
- `access/accesskey` — retrieves license access key

# access/delapikey

**Category**: users  
**Firmware tested**: 7.2.54.12.22642.RELEASE  
**PS Cmdlet**: `Remove-SecApiKey`

## Description

Removes sec API key.

## Endpoint

```text
POST https://<host>:<port>/access/delapikey?apikey=<apikey>&key=<key>&user=<user>
```

## HTTP Method

`POST` — write/modify operation.

## Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `apikey` | string | No | API key used instead of basic-auth credentials. |
| `key` | string | No | API key value to list or delete. |
| `user` | string | No | User name for the local or remote user entry. |

## Example Request

```bash
curl -sk -u "bal:PASSWORD" -X POST "https://LOADMASTER_HOST:443/access/delapikey?apikey=YOUR_API_KEY&key=YOUR_KEY_ID&user=apiuser"
```

## Example Response (XML)

```xml
<?xml version="1.0" encoding="ISO-8859-1"?>
<Response stat="200" code="ok">
  <Success>
    <Data>
      <!-- delapikey operation completed -->
    </Data>
  </Success>
</Response>
```


## Example Request (APIv2)

```bash
curl -sk -X POST "https://10.0.0.69:443/accessv2" \
  -H "Content-Type: application/json" \
  -d '{"apiuser":"bal","apipass":"PASSWORD","cmd":"delapikey","apikey":"example","key":"0123456789abcdef","user":"ExampleUser"}'
```

## Notes

- API v1 responses are XML. Do not expect JSON payloads from the main response body.
- The reference guide shows multiple endpoint forms for this command, including alternate addressing by ID or name where applicable.
- Although the legacy API is query-string driven, document new automation as a write operation because it changes appliance state.

## See Also

- `access/addapikey` — creates sec API key

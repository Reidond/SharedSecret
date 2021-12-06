# Shared Secret

Decrypt shared secret from your [Steam Desktop Authenticator](https://github.com/Jessecar96/SteamDesktopAuthenticator)

## Usage

```powershell
$Env:S2FAENCRYPTKEY = "<YOUR KEY HERE>"; .\bin\Release\net6.0\SharedSecret.exe "C:\Program Files\SDA\maFiles\manifest.json"
```

```json
[
  {
    "steam_id": "76561198117480403",
    "shared_secret": ""
  }
]
```

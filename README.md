# Authon AutoIt SDK

<p align="center">
  <img src="https://authon.pro/logo.png" alt="Authon" width="80" />
  <br/>
  <strong>Official AutoIt SDK for Authon — Software Licensing & Authentication Platform</strong>
</p>

<p align="center">
  <a href="https://authon.pro">Website</a> •
  <a href="https://authon.pro/docs">Docs</a> •
  <a href="https://discord.gg/jMZCTKPsmE">Discord</a> •
  <a href="https://authon.pro/status">Status</a>
</p>

---

## Requirements

- AutoIt v3
- WinHTTP UDF (included with AutoIt)

## Quick Start

```autoit
#include "Authon.au3"

Authon_Init("your-app-id", "your-api-key")
If Authon_Connect() Then
    MsgBox(0, "Connected", $AUTHON_APP_NAME & " v" & $AUTHON_APP_VERSION)
EndIf

If Authon_Login("username", "password") Then
    MsgBox(0, "Auth", "Level: " & $AUTHON_LEVEL)
EndIf

Authon_Logout()
```

## Links

- 🌐 Website: https://authon.pro
- 📖 Docs: https://authon.pro/docs
- 💬 Discord: https://discord.gg/jMZCTKPsmE
- 📊 Status: https://authon.pro/status

## License

MIT

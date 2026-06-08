; ╔══════════════════════════════════════════════════════════════════════════════╗
; ║  Authon AutoIt SDK — Software Licensing & Authentication                   ║
; ║  Version: 1.0.0                                                            ║
; ║  Dependencies: WinHTTP UDF (built-in)                                      ║
; ║                                                                            ║
; ║  Website: https://authon.pro                                               ║
; ║  Docs:    https://authon.pro/docs                                          ║
; ║  Discord: https://discord.gg/jMZCTKPsmE                                    ║
; ║  Status:  https://authon.pro/status                                        ║
; ║  Health:  https://api.authon.pro/health                                    ║
; ║  GitHub:  https://github.com/authonpro                                     ║
; ║                                                                            ║
; ║  Usage:                                                                    ║
; ║    #include "Authon.au3"                                                   ║
; ║    _Authon_Init("app-id", "api-key")                                       ║
; ║    _Authon_Connect()                                                       ║
; ║    Local $result = _Authon_Login("user", "pass")                           ║
; ║    If $result Then MsgBox(0, "Success", "Welcome " & $g_AuthonUsername)    ║
; ╚══════════════════════════════════════════════════════════════════════════════╝

#include-once
#include <WinHTTP.au3>
#include <String.au3>

; ═══════════════════════════════════════════════════════════════════════════════
; GLOBAL STATE
; ═══════════════════════════════════════════════════════════════════════════════

Global Const $AUTHON_VERSION = "1.0.0"
Global Const $AUTHON_API_URL = "https://api.authon.pro/v1"

; Configuration
Global $g_AuthonAppId = ""
Global $g_AuthonApiKey = ""
Global $g_AuthonApiUrl = $AUTHON_API_URL

; Session state
Global $g_AuthonSessionToken = ""
Global $g_AuthonUsername = ""
Global $g_AuthonLevel = 0
Global $g_AuthonSubscription = ""
Global $g_AuthonExpiresAt = ""

; App info
Global $g_AuthonAppName = ""
Global $g_AuthonAppVersion = ""
Global $g_AuthonHwidLock = False
Global $g_AuthonHashCheck = False
Global $g_AuthonInitialized = False

; Last error
Global $g_AuthonLastError = ""

; ═══════════════════════════════════════════════════════════════════════════════
; INITIALIZATION
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_Init
; Description: Configures the Authon SDK with application credentials.
;              Must be called before any other function.
; Parameters:  $sAppId  - Your Application ID from the Authon dashboard
;              $sApiKey - Your API Key from the Authon dashboard
;              $sApiUrl - [Optional] Custom API URL
; Returns:     None
; ==============================================================================
Func _Authon_Init($sAppId, $sApiKey, $sApiUrl = "")
    If $sAppId = "" Or $sApiKey = "" Then
        $g_AuthonLastError = "AppId and ApiKey are required"
        Return SetError(1, 0, False)
    EndIf

    $g_AuthonAppId = $sAppId
    $g_AuthonApiKey = $sApiKey
    If $sApiUrl <> "" Then $g_AuthonApiUrl = $sApiUrl
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_Connect
; Description: Initializes the connection to the Authon API.
;              Validates credentials and retrieves app info.
; Returns:     True if successful, False otherwise.
;              On success: sets $g_AuthonAppName, $g_AuthonAppVersion, etc.
; ==============================================================================
Func _Authon_Connect()
    Local $sPayload = _Authon_BuildJson("type", "init")
    Local $sResponse = _Authon_Request($sPayload)

    If @error Then Return SetError(1, 0, False)

    If _Authon_JsonGetBool($sResponse, "success") Then
        $g_AuthonAppName = _Authon_JsonGetString($sResponse, "name")
        $g_AuthonAppVersion = _Authon_JsonGetString($sResponse, "version")
        $g_AuthonHwidLock = _Authon_JsonGetBool($sResponse, "hwidLock")
        $g_AuthonHashCheck = _Authon_JsonGetBool($sResponse, "hashCheck")
        $g_AuthonInitialized = True
        Return True
    Else
        $g_AuthonLastError = _Authon_JsonGetString($sResponse, "message")
        Return False
    EndIf
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; HWID GENERATION
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_GetHWID
; Description: Generates a hardware ID unique to the current machine.
;              Uses disk serial number + computer name, hashed with MD5.
; Returns:     String - 32-character lowercase hex MD5 hash.
; ==============================================================================
Func _Authon_GetHWID()
    Local $sRaw = ""

    ; Get disk serial number via WMI
    Local $oWMI = ObjGet("winmgmts:\\.\root\CIMV2")
    If IsObj($oWMI) Then
        Local $oDisks = $oWMI.ExecQuery("SELECT SerialNumber FROM Win32_DiskDrive WHERE Index=0")
        If IsObj($oDisks) Then
            For $oDisk In $oDisks
                $sRaw = StringStripWS($oDisk.SerialNumber, 3)
                ExitLoop
            Next
        EndIf
    EndIf

    ; Append computer name
    $sRaw &= @ComputerName

    ; Fallback
    If $sRaw = "" Then $sRaw = @ComputerName & @UserName

    ; MD5 hash
    Return _Authon_MD5($sRaw)
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; AUTHENTICATION
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_Login
; Description: Authenticates with username and password.
;              On success, sets session state globals.
; Parameters:  $sUsername - User's username
;              $sPassword - User's password
;              $sHwid     - [Optional] Hardware ID (auto-generated if empty)
; Returns:     True if login successful, False otherwise.
;              Check $g_AuthonLastError for error details.
; Possible errors: "Invalid credentials", "Account banned",
;                  "Hardware ID mismatch", "Subscription expired"
; ==============================================================================
Func _Authon_Login($sUsername, $sPassword, $sHwid = "")
    If $sUsername = "" Or $sPassword = "" Then
        $g_AuthonLastError = "Username and password are required"
        Return False
    EndIf

    If $sHwid = "" Then $sHwid = _Authon_GetHWID()

    Local $sPayload = _Authon_BuildJson("type", "login", "username", $sUsername, "password", $sPassword, "hwid", $sHwid)
    Local $sResponse = _Authon_Request($sPayload)

    If @error Then Return SetError(1, 0, False)

    If _Authon_JsonGetBool($sResponse, "success") Then
        $g_AuthonSessionToken = _Authon_JsonGetString($sResponse, "sessionToken")
        $g_AuthonUsername = _Authon_JsonGetString($sResponse, "username")
        $g_AuthonLevel = Number(_Authon_JsonGetString($sResponse, "level"))
        $g_AuthonSubscription = _Authon_JsonGetString($sResponse, "subscription")
        $g_AuthonExpiresAt = _Authon_JsonGetString($sResponse, "expiresAt")
        Return True
    Else
        $g_AuthonLastError = _Authon_JsonGetString($sResponse, "message")
        Return False
    EndIf
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_License
; Description: Authenticates using a license key only.
; Parameters:  $sLicenseKey - The license key
;              $sHwid       - [Optional] Hardware ID
; Returns:     True if successful, False otherwise.
; ==============================================================================
Func _Authon_License($sLicenseKey, $sHwid = "")
    If $sLicenseKey = "" Then
        $g_AuthonLastError = "License key is required"
        Return False
    EndIf

    If $sHwid = "" Then $sHwid = _Authon_GetHWID()

    Local $sPayload = _Authon_BuildJson("type", "license", "licenseKey", $sLicenseKey, "hwid", $sHwid)
    Local $sResponse = _Authon_Request($sPayload)

    If @error Then Return SetError(1, 0, False)

    If _Authon_JsonGetBool($sResponse, "success") Then
        $g_AuthonSessionToken = _Authon_JsonGetString($sResponse, "sessionToken")
        $g_AuthonUsername = _Authon_JsonGetString($sResponse, "username")
        $g_AuthonLevel = Number(_Authon_JsonGetString($sResponse, "level"))
        $g_AuthonSubscription = _Authon_JsonGetString($sResponse, "subscription")
        $g_AuthonExpiresAt = _Authon_JsonGetString($sResponse, "expiresAt")
        Return True
    Else
        $g_AuthonLastError = _Authon_JsonGetString($sResponse, "message")
        Return False
    EndIf
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_Register
; Description: Registers a new user account with a license key.
; Parameters:  $sUsername   - Desired username
;              $sPassword   - Desired password
;              $sLicenseKey - A valid, unused license key
;              $sHwid       - [Optional] Hardware ID
; Returns:     True if successful, False otherwise.
; ==============================================================================
Func _Authon_Register($sUsername, $sPassword, $sLicenseKey, $sHwid = "")
    If $sUsername = "" Or $sPassword = "" Or $sLicenseKey = "" Then
        $g_AuthonLastError = "Username, password, and license key are required"
        Return False
    EndIf

    If $sHwid = "" Then $sHwid = _Authon_GetHWID()

    Local $sPayload = _Authon_BuildJson("type", "register", "username", $sUsername, "password", $sPassword, "licenseKey", $sLicenseKey, "hwid", $sHwid)
    Local $sResponse = _Authon_Request($sPayload)

    If @error Then Return SetError(1, 0, False)

    If _Authon_JsonGetBool($sResponse, "success") Then
        Return True
    Else
        $g_AuthonLastError = _Authon_JsonGetString($sResponse, "message")
        Return False
    EndIf
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; SESSION MANAGEMENT
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_Check
; Description: Validates the current session (heartbeat).
; Returns:     True if session is valid, False otherwise.
; ==============================================================================
Func _Authon_Check()
    If $g_AuthonSessionToken = "" Then Return False

    Local $sPayload = _Authon_BuildJson("type", "check", "sessionToken", $g_AuthonSessionToken)
    Local $sResponse = _Authon_Request($sPayload)

    If @error Then Return False
    Return _Authon_JsonGetBool($sResponse, "success")
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_Logout
; Description: Ends the current session and clears local state.
; Returns:     True if logout successful, False otherwise.
; ==============================================================================
Func _Authon_Logout()
    If $g_AuthonSessionToken = "" Then Return False

    Local $sPayload = _Authon_BuildJson("type", "logout", "sessionToken", $g_AuthonSessionToken)
    Local $sResponse = _Authon_Request($sPayload)

    If @error Then Return False

    If _Authon_JsonGetBool($sResponse, "success") Then
        $g_AuthonSessionToken = ""
        $g_AuthonUsername = ""
        $g_AuthonLevel = 0
        $g_AuthonSubscription = ""
        $g_AuthonExpiresAt = ""
        Return True
    EndIf
    Return False
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; VARIABLES
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_GetVar
; Description: Gets an application-level variable.
; Parameters:  $sKey - Variable name
; Returns:     String - Variable value, or "" if not found.
; ==============================================================================
Func _Authon_GetVar($sKey)
    Local $sPayload = _Authon_BuildJson("type", "var", "key", $sKey, "sessionToken", $g_AuthonSessionToken)
    Local $sResponse = _Authon_Request($sPayload)
    If @error Then Return ""
    If _Authon_JsonGetBool($sResponse, "success") Then
        Return _Authon_JsonGetString($sResponse, "value")
    EndIf
    Return ""
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_SetVar
; Description: Sets a user-level variable.
; Parameters:  $sKey   - Variable name
;              $sValue - Variable value
; Returns:     True if saved, False otherwise.
; ==============================================================================
Func _Authon_SetVar($sKey, $sValue)
    Local $sPayload = _Authon_BuildJson("type", "setvar", "key", $sKey, "value", $sValue, "sessionToken", $g_AuthonSessionToken)
    Local $sResponse = _Authon_Request($sPayload)
    If @error Then Return False
    Return _Authon_JsonGetBool($sResponse, "success")
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_GetUserVar
; Description: Gets a user-level variable.
; Parameters:  $sKey - Variable name
; Returns:     String - Variable value, or "" if not found.
; ==============================================================================
Func _Authon_GetUserVar($sKey)
    Local $sPayload = _Authon_BuildJson("type", "getvar", "key", $sKey, "sessionToken", $g_AuthonSessionToken)
    Local $sResponse = _Authon_Request($sPayload)
    If @error Then Return ""
    If _Authon_JsonGetBool($sResponse, "success") Then
        Return _Authon_JsonGetString($sResponse, "value")
    EndIf
    Return ""
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; FILES
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_ListFiles
; Description: Lists files available to the authenticated user.
; Returns:     String - Raw JSON response (parse with _Authon_JsonGetString)
; ==============================================================================
Func _Authon_ListFiles()
    Local $sPayload = _Authon_BuildJson("type", "list_files", "sessionToken", $g_AuthonSessionToken)
    Return _Authon_Request($sPayload)
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_DownloadFile
; Description: Downloads a file by its ID and saves it to disk.
; Parameters:  $sFileId    - File ID from _Authon_ListFiles
;              $sOutputPath - Path to save the file
; Returns:     True if download successful, False otherwise.
; ==============================================================================
Func _Authon_DownloadFile($sFileId, $sOutputPath)
    If $g_AuthonSessionToken = "" Or $sFileId = "" Then Return False

    Local $sPayload = _Authon_BuildJson("type", "file", "fileId", $sFileId, "sessionToken", $g_AuthonSessionToken)

    ; Use WinHTTP directly for binary download
    Local $hOpen = _WinHttpOpen("Authon-AutoIt-SDK/" & $AUTHON_VERSION)
    Local $hConnect = _WinHttpConnect($hOpen, "api.authon.pro", 443)
    Local $hRequest = _WinHttpOpenRequest($hConnect, "POST", "/v1", "", "", "", $WINHTTP_FLAG_SECURE)

    _WinHttpAddRequestHeaders($hRequest, "Content-Type: application/json")
    _WinHttpSendRequest($hRequest, "", $sPayload)
    _WinHttpReceiveResponse($hRequest)

    Local $sData = _WinHttpReadData($hRequest, 2) ; Binary mode
    _WinHttpCloseHandle($hRequest)
    _WinHttpCloseHandle($hConnect)
    _WinHttpCloseHandle($hOpen)

    If BinaryLen($sData) > 0 Then
        Local $hFile = FileOpen($sOutputPath, 18) ; Binary + Overwrite
        FileWrite($hFile, $sData)
        FileClose($hFile)
        Return True
    EndIf

    Return False
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; LOGGING & ANALYTICS
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_Log
; Description: Sends an activity log message to the dashboard.
; Parameters:  $sMessage - Log message (max 500 chars)
; Returns:     True if logged, False otherwise.
; ==============================================================================
Func _Authon_Log($sMessage)
    If StringLen($sMessage) > 500 Then $sMessage = StringLeft($sMessage, 500)
    Local $sPayload = _Authon_BuildJson("type", "log", "message", $sMessage, "sessionToken", $g_AuthonSessionToken)
    Local $sResponse = _Authon_Request($sPayload)
    If @error Then Return False
    Return _Authon_JsonGetBool($sResponse, "success")
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_FetchOnline
; Description: Gets the list of currently online users.
; Returns:     String - Raw JSON response
; ==============================================================================
Func _Authon_FetchOnline()
    Local $sPayload = _Authon_BuildJson("type", "fetch_online", "sessionToken", $g_AuthonSessionToken)
    Return _Authon_Request($sPayload)
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_FetchStats
; Description: Gets application statistics.
; Returns:     String - Raw JSON response
; ==============================================================================
Func _Authon_FetchStats()
    Local $sPayload = _Authon_BuildJson("type", "fetch_stats", "sessionToken", $g_AuthonSessionToken)
    Return _Authon_Request($sPayload)
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; SECURITY
; ═══════════════════════════════════════════════════════════════════════════════

; #FUNCTION# ===================================================================
; Name:        _Authon_CheckBlacklist
; Description: Checks if an IP or HWID is blacklisted.
; Parameters:  $sIP   - IP address (optional, pass "" to skip)
;              $sHwid - HWID (optional, pass "" to skip)
; Returns:     String - Raw JSON response
; ==============================================================================
Func _Authon_CheckBlacklist($sIP = "", $sHwid = "")
    Local $sExtra = ""
    If $sIP <> "" Then $sExtra &= ',"ip":"' & _Authon_JsonEscape($sIP) & '"'
    If $sHwid <> "" Then $sExtra &= ',"hwid":"' & _Authon_JsonEscape($sHwid) & '"'

    Local $sPayload = '{"type":"check_blacklist","appId":"' & _Authon_JsonEscape($g_AuthonAppId) & '","apiKey":"' & _Authon_JsonEscape($g_AuthonApiKey) & '"' & $sExtra & '}'
    Return _Authon_Request($sPayload)
EndFunc

; #FUNCTION# ===================================================================
; Name:        _Authon_RedeemReferral
; Description: Redeems a referral code for bonus subscription days.
; Parameters:  $sCode - Referral code
; Returns:     String - Raw JSON response
; ==============================================================================
Func _Authon_RedeemReferral($sCode)
    Local $sPayload = _Authon_BuildJson("type", "redeem_referral", "code", $sCode, "sessionToken", $g_AuthonSessionToken)
    Return _Authon_Request($sPayload)
EndFunc

; ═══════════════════════════════════════════════════════════════════════════════
; INTERNAL FUNCTIONS
; ═══════════════════════════════════════════════════════════════════════════════

; Sends a POST request to the Authon API.
Func _Authon_Request($sJsonBody)
    Local $hOpen = _WinHttpOpen("Authon-AutoIt-SDK/" & $AUTHON_VERSION)
    If @error Then
        $g_AuthonLastError = "Failed to open WinHTTP session"
        Return SetError(1, 0, "")
    EndIf

    Local $hConnect = _WinHttpConnect($hOpen, "api.authon.pro", 443)
    If @error Then
        _WinHttpCloseHandle($hOpen)
        $g_AuthonLastError = "Failed to connect to API"
        Return SetError(1, 0, "")
    EndIf

    Local $hRequest = _WinHttpOpenRequest($hConnect, "POST", "/v1", "", "", "", $WINHTTP_FLAG_SECURE)
    If @error Then
        _WinHttpCloseHandle($hConnect)
        _WinHttpCloseHandle($hOpen)
        $g_AuthonLastError = "Failed to create request"
        Return SetError(1, 0, "")
    EndIf

    _WinHttpAddRequestHeaders($hRequest, "Content-Type: application/json")
    _WinHttpSendRequest($hRequest, "", $sJsonBody)
    _WinHttpReceiveResponse($hRequest)

    Local $sResponse = _WinHttpReadData($hRequest)

    _WinHttpCloseHandle($hRequest)
    _WinHttpCloseHandle($hConnect)
    _WinHttpCloseHandle($hOpen)

    Return $sResponse
EndFunc

; Builds a JSON payload string from key-value pairs.
Func _Authon_BuildJson($key1 = "", $val1 = "", $key2 = "", $val2 = "", $key3 = "", $val3 = "", $key4 = "", $val4 = "", $key5 = "", $val5 = "", $key6 = "", $val6 = "")
    Local $sJson = '{"appId":"' & _Authon_JsonEscape($g_AuthonAppId) & '","apiKey":"' & _Authon_JsonEscape($g_AuthonApiKey) & '"'

    If $key1 <> "" Then $sJson &= ',"' & $key1 & '":"' & _Authon_JsonEscape($val1) & '"'
    If $key2 <> "" Then $sJson &= ',"' & $key2 & '":"' & _Authon_JsonEscape($val2) & '"'
    If $key3 <> "" Then $sJson &= ',"' & $key3 & '":"' & _Authon_JsonEscape($val3) & '"'
    If $key4 <> "" Then $sJson &= ',"' & $key4 & '":"' & _Authon_JsonEscape($val4) & '"'
    If $key5 <> "" Then $sJson &= ',"' & $key5 & '":"' & _Authon_JsonEscape($val5) & '"'
    If $key6 <> "" Then $sJson &= ',"' & $key6 & '":"' & _Authon_JsonEscape($val6) & '"'

    $sJson &= '}'
    Return $sJson
EndFunc

; Escapes a string for JSON.
Func _Authon_JsonEscape($sStr)
    $sStr = StringReplace($sStr, '\', '\\')
    $sStr = StringReplace($sStr, '"', '\"')
    $sStr = StringReplace($sStr, @CR, '\r')
    $sStr = StringReplace($sStr, @LF, '\n')
    $sStr = StringReplace($sStr, @TAB, '\t')
    Return $sStr
EndFunc

; Extracts a string value from JSON by key (simple parser).
Func _Authon_JsonGetString($sJson, $sKey)
    Local $sSearch = '"' & $sKey & '"'
    Local $iPos = StringInStr($sJson, $sSearch)
    If $iPos = 0 Then Return ""

    ; Find the colon after the key
    $iPos = StringInStr($sJson, ":", 0, 1, $iPos + StringLen($sSearch))
    If $iPos = 0 Then Return ""

    ; Skip whitespace
    Local $i = $iPos + 1
    While $i <= StringLen($sJson) And (StringMid($sJson, $i, 1) = " " Or StringMid($sJson, $i, 1) = @TAB)
        $i += 1
    WEnd

    ; Check for null
    If StringMid($sJson, $i, 4) = "null" Then Return ""

    ; Check for string value
    If StringMid($sJson, $i, 1) = '"' Then
        $i += 1
        Local $sValue = ""
        While $i <= StringLen($sJson)
            Local $char = StringMid($sJson, $i, 1)
            If $char = '\' And $i + 1 <= StringLen($sJson) Then
                Local $next = StringMid($sJson, $i + 1, 1)
                Switch $next
                    Case '"'
                        $sValue &= '"'
                    Case '\'
                        $sValue &= '\'
                    Case 'n'
                        $sValue &= @LF
                    Case 'r'
                        $sValue &= @CR
                    Case Else
                        $sValue &= $next
                EndSwitch
                $i += 2
            ElseIf $char = '"' Then
                ExitLoop
            Else
                $sValue &= $char
                $i += 1
            EndIf
        WEnd
        Return $sValue
    EndIf

    ; Number or boolean
    Local $sValue = ""
    While $i <= StringLen($sJson)
        Local $c = StringMid($sJson, $i, 1)
        If $c = "," Or $c = "}" Or $c = "]" Then ExitLoop
        $sValue &= $c
        $i += 1
    WEnd
    Return StringStripWS($sValue, 3)
EndFunc

; Gets a boolean value from JSON.
Func _Authon_JsonGetBool($sJson, $sKey)
    Local $sVal = _Authon_JsonGetString($sJson, $sKey)
    Return ($sVal = "true" Or $sVal = "1")
EndFunc

; Computes MD5 hash.
Func _Authon_MD5($sString)
    Local $hProv = DllCall("advapi32.dll", "bool", "CryptAcquireContextW", "ptr*", 0, "ptr", 0, "ptr", 0, "dword", 1, "dword", 0xF0000000)
    If @error Or Not $hProv[0] Then Return ""

    Local $hHash = DllCall("advapi32.dll", "bool", "CryptCreateHash", "ptr", $hProv[1], "uint", 0x8003, "ptr", 0, "dword", 0, "ptr*", 0)
    If @error Or Not $hHash[0] Then
        DllCall("advapi32.dll", "bool", "CryptReleaseContext", "ptr", $hProv[1], "dword", 0)
        Return ""
    EndIf

    Local $bData = StringToBinary($sString, 4) ; UTF-8
    Local $iLen = BinaryLen($bData)
    Local $tData = DllStructCreate("byte[" & $iLen & "]")
    DllStructSetData($tData, 1, $bData)

    DllCall("advapi32.dll", "bool", "CryptHashData", "ptr", $hHash[5], "struct*", $tData, "dword", $iLen, "dword", 0)

    Local $tHash = DllStructCreate("byte[16]")
    Local $tSize = DllStructCreate("dword")
    DllStructSetData($tSize, 1, 16)

    DllCall("advapi32.dll", "bool", "CryptGetHashParam", "ptr", $hHash[5], "dword", 2, "struct*", $tHash, "struct*", $tSize, "dword", 0)

    DllCall("advapi32.dll", "bool", "CryptDestroyHash", "ptr", $hHash[5])
    DllCall("advapi32.dll", "bool", "CryptReleaseContext", "ptr", $hProv[1], "dword", 0)

    Local $sHex = ""
    For $i = 1 To 16
        $sHex &= StringLower(Hex(DllStructGetData($tHash, 1, $i), 2))
    Next

    Return $sHex
EndFunc

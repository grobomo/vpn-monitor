Set WshShell = CreateObject("WScript.Shell")
WshShell.Run "pythonw.exe """ & Replace(WScript.ScriptFullName, "vpn_reconnect.vbs", "vpn_reconnect.py") & """", 0, False

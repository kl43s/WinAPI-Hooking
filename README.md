# WinAPI-Hooking
## Poucave.sys
Driver to intercept process creation notification and communicate it with injector for the api hook process.
```bash
sc create poucave binPath=<path to the driver> type=kernel
sc start poucave
```

## Injector32.exe / Injector64.exe
Program to inject the hooker in a targeted process.
```bash
start Injector32.exe
start Injector64.exe
```

## Hooker32.dll / Hooker64.dll
DLL loading into a targeted process to hook a WinAPI function and the return address.

Reference : https://sealkisnotklaes.fr/articles/winapi-hooking-used-by-malware

C:
cls
@Echo File by Kauan Fonseca
:: Limpar pasta temp ::
@Echo Off
echo.
echo -----------------------------------
echo         Limpando Pasta Temp
echo -----------------------------------
echo.

RD /S /Q "temp" 
takeown /f "temp" /r /d y
takeown /f "C:\Windows\Temp" /r /d y
RD /S /Q "C:\Windows\Temp"
takeown /f "C:\Windows\Temp" /r /d y
del /s /f /q C:\windows\temp\*.*
del /s /f /q temp\*.*
rd /s /q C:\windows\temp
rd /s /q temp

takeown /f "temp" /r /d y
takeown /f "C:\Windows\Temp" /r /d y
RD /S /Q "C:\Windows\Temp"
del /s /f /q "C:\Windows\Temp\*.*"
RD /S /Q "C:\Windows\Temp"
del /q C:\Windows\Temp\*.* > nul 2>&1

:: Limpar pasta %temp% ::
@Echo Off
echo -----------------------------------
echo        Limpando Pasta Temp
echo -----------------------------------
echo.

RD /S /Q "%temp%"
takeown /f "%temp%" /r /d y
takeown /f "C:\Users\%USERNAME%\AppData\Local\Temp" /r /d y
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\Temp"
takeown /f "C:\Users\%USERNAME%\AppData\Local\Temp" /r /d y
takeown /f "%temp%" /r /d y
del /s /f /q C:\windows\%temp%\*.*
del "%temp%" /s /f /q
del /s /f /q %temp%\*.*
rd /s /q C:\windows\%temp%
rd /s /q %temp%

takeown /f "%temp%" /r /d y
takeown /f "C:\Users\%USERNAME%\AppData\Local\Temp" /r /d y
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\Temp"
del /s /f /q "C:\Users\%USERNAME%\AppData\Local\Temp\*.*"
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\Temp"
del /q C:\Users\%USERNAME%\AppData\Local\Temp\*.* > nul 2>&1

:: Limpar pasta Prefetch ::
@Echo Off
echo.
echo -----------------------------------
echo       Limpando Pasta Prefetch
echo -----------------------------------
echo.

RD /S /Q "Prefetch"
takeown /f "Prefetch" /r /d y
takeown /f "C:\Windows\Prefetch" /r /d y
RD /S /Q "C:\Windows\Prefetch"
takeown /f "C:\Windows\Prefetch" /r /d y
takeown /f "Prefetch" /r /d y
del /s /f /q C:\windows\Prefetch\*.*
del "Prefetch" /s /f /q
del /s /f /q Prefetch\*.*
rd /s /q C:\windows\Prefetch
rd /s /q Prefetch

takeown /f "Prefetch" /r /d y
takeown /f "C:\Windows\Prefetch" /r /d y
RD /S /Q "C:\Windows\Prefetch"
del /s /f /q "C:\Windows\Prefetch\*.*"
RD /S /Q "C:\Windows\Prefetch"
del /q C:\Windows\Prefetch\*.* > nul 2>&1

:: Limpar pasta Recent ::
@Echo Off 
echo.
echo -----------------------------------
echo         Limpando Pasta Recent
echo -----------------------------------
echo.

RD /S /Q "recent"
takeown /f "recent" /r /d y
takeown /f "C:\Windows\Recent" /r /d y
RD /S /Q "C:\Windows\Recent"
takeown /f "C:\Windows\Recent" /r /d y
takeown /f "recent" /r /d y
del /s /f /q C:\windows\recent\*.*
del "recent" /s /f /q
del /s /f /q recent\*.*
rd /s /q C:\windows\recent
rd /s /q recent

takeown /f "recent" /r /d y
takeown /f "C:\Windows\Recent" /r /d y
RD /S /Q "C:\Windows\Recent"
del /s /f /q "C:\Windows\Recent\*.*"
RD /S /Q "C:\Windows\Recent"
del /q C:\Windows\Recent\*.* > nul 2>&1

:: Limpar pasta Pip ::
@Echo Off
echo.
echo -----------------------------------
echo         Limpando Pasta Pip
echo -----------------------------------
echo.

RD /S /Q "pip"
takeown /f "pip" /r /d y
takeown /f "C:\Users\%USERNAME%\AppData\Local\pip" /r /d y
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\pip"
takeown /f "C:\Users\%USERNAME%\AppData\Local\pip" /r /d y
takeown /f "pip" /r /d y
del /s /f /q C:\windows\pip\*.*
del "pip" /s /f /q
del /s /f /q pip\*.*
rd /s /q C:\windows\pip
rd /s /q pip

takeown /f "pip" /r /d y
takeown /f "C:\Users\%USERNAME%\AppData\Local\pip" /r /d y
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\pip"
del /s /f /q "C:\Users\%USERNAME%\AppData\Local\pip\*.*"
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\pip"
rmdir /s /q C:\Users\%USERNAME%\AppData\Local\pip > nul 2>&1

:: Limpar pasta Cache ::
@Echo Off
echo.
echo -----------------------------------
echo         Limpando Pasta Cache
echo -----------------------------------
echo.

RD /S /Q "cache"
takeown /f "cache" /r /d y
takeown /f "C:\Users\%USERNAME%\AppData\Local\cache" /r /d y
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\cache"
takeown /f "C:\Users\%USERNAME%\AppData\Local\cache" /r /d y
takeown /f "cache" /r /d y
del /s /f /q C:\windows\cache\*.*
del "cache" /s /f /q
del /s /f /q cache\*.*
rd /s /q C:\windows\cache
rd /s /q cache

takeown /f "cache" /r /d y
takeown /f "C:\Users\%USERNAME%\AppData\Local\cache" /r /d y
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\cache"
del /s /f /q "C:\Users\%USERNAME%\AppData\Local\cache\*.*"
RD /S /Q "C:\Users\%USERNAME%\AppData\Local\cache"
rmdir /s /q C:\Users\%USERNAME%\AppData\Local\cache > nul 2>&1

:: Limpar pasta Logs ::
@Echo Off
echo.
echo -----------------------------------
echo         Limpando Pasta Logs
echo -----------------------------------
echo.

RD /S /Q "Logs"
takeown /f "Logs" /r /d y
takeown /f "C:\Windows\Logs" /r /d y
RD /S /Q "C:\Windows\Logs"
takeown /f "C:\Windows\Logs" /r /d y
takeown /f "Logs" /r /d y
del /s /f /q C:\Windows\Logs\*.*
del "Logs" /s /f /q
del /s /f /q Logs\*.*
rd /s /q C:\Windows\Logs
rd /s /q Logs

takeown /f "Logs" /r /d y
takeown /f "C:\Windows\Logs" /r /d y
RD /S /Q "C:\Windows\Logs"
del /s /f /q "C:\Windows\Logs\*.*"
RD /S /Q "C:\Windows\Logs"
rmdir /s /q C:\Windows\Logs > nul 2>&1

:: Limpar pesquisas ::
@Echo Off
echo.
echo -----------------------------------
echo         Limpando Pasta Pesquisas
echo -----------------------------------
echo.

RD /S /Q "Searches"
takeown /f "Searches" /r /d y
takeown /f "C:\Users\Cowanbas\Searches" /r /d y
RD /S /Q "C:\Users\Cowanbas\Searches"
takeown /f "C:\Users\Cowanbas\Searches" /r /d y
takeown /f "Searches" /r /d y
del /s /f /q C:\Users\Cowanbas\Searches\*.*
del "Searches" /s /f /q
del /s /f /q Searches\*.*
rd /s /q C:\Users\Cowanbas\Searches
rd /s /q Searches

takeown /f "Searches" /r /d y
takeown /f "C:\Users\Cowanbas\Searches" /r /d y
RD /S /Q "C:\Users\Cowanbas\Searches"
del /s /f /q "C:\Users\Cowanbas\Searches\*.*"
RD /S /Q "C:\Users\Cowanbas\Searches"
rmdir /s /q C:\Users\%USERNAME%\Searches > nul 2>&1

:: Deletando arquivo temporario ::
@Echo Off
echo.
echo -----------------------------------
echo     Deletando arquivos temporario
echo -----------------------------------
echo.

set "steamLogsPath=D:\2 GAMES\1 STEAM\logs"
set "vanguardLogsPath=C:\Program Files\Riot Vanguard\Logs"

del $null 
del index.dat/S 
del c:\WIN386.SWP 
Del /q/f/a/s *.gif 
del *.log /a /s /q /f
del "%temp%" /s /f /q
del /q /s C:\Windows\*.log 
del c:\$recycle.bin\* /s /q 
del "%WINDIR%\Logs" /s /f /q 
del /q /s C:\Windows\Temp\*.* 
del /q "%steamLogsPath%\*.log"
del /q "%steamLogsPath%\*.txt"
del /q "%vanguardLogsPath%\*.log"
del /q "%vanguardLogsPath%\*.txt"
del /q /s /f %LocalAppData%\Temp\* 
del /s /f /q %SYSTEMDRIVE%\AMD\*.* 
del /s /f /q %SYSTEMDRIVE%\INTEL\*.*
del /s /f /q %SYSTEMDRIVE%\NVIDIA\*.* 
del "%AppData%\Discord\Cache\." /s /f /q 
del "%ProgramData%\USOShared\Logs" /s /f /q 
del "%AppData%\Discord\Code Cache\." /s /f /q 
del "C:\Windows\System32\SleepStudy" /s /f /q 
del "%WINDIR%\Installer\$PatchCache$" /s /f /q 
del "%ProgramData%\USOPrivate\UpdateStore" /s /f /q 
del /q /s /f %LocalAppData%\Microsoft\Windows\INetCache\* 
del /q /s /f %SystemRoot%\SoftwareDistribution\DataStore\* 
del "%LocalAppData%\Microsoft\Windows\INetCache\." /s /f /q 
del "%AppData%\Local\Microsoft\Windows\INetCookies\." /s /f /q 
del /q /s /f %LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db 
del /q /s /f %LocalAppData%\Microsoft\Windows\Temporary Internet Files\* 

rd /s /q C:\$Recycle.bin 
rd /s /q %SYSTEMDRIVE%\AMD 
rd /s /q %LocalAppData%\Temp 
rd /s /q %SYSTEMDRIVE%\INTEL 
rd /s /q %SYSTEMDRIVE%\NVIDIA 
rd "%AppData%\Discord\Cache" /s /q 
rd "%SystemDrive%\$SysReset" /s /q 
rd "%SystemDrive%\$GetCurrent" /s /q 
rd "%SystemDrive%\$WinREAgent" /s /q 
rd "%SystemDrive%\OneDriveTemp" /s /q 
rd "%SystemDrive%\$Windows.~BT" /s /q
rd "%SystemDrive%\$Windows.~WS" /s /q 
rd "%AppData%\Discord\Code Cache" /s /q 
rd /s /q %LocalAppData%\Temp\mozilla-temp-files 

rmdir /S /Q "%AppData%\Local\Temp\" 
rmdir /s /q "%SystemRoot%\System32\SleepStudy" 
rmdir /S /Q "%LocalAppData%\Microsoft\Windows\WebCache"
rmdir /s /q "%SystemRoot%\System32\SleepStudy >nul 2>&1" 
rmdir /S /Q "%AppData%\Local\Microsoft\Windows\INetCache\" 
rmdir /S /Q "%AppData%\Local\Microsoft\Windows\INetCookies" 

:: Removendo historico da área de transferencia::

cmd /c "echo off | clip"

:: Parando serviços ::

sc stop "vgc" > nul 2>&1
sc stop "zksvc" > nul 2>&1
sc stop "wuauserv" > nul 2>&1
sc stop "BEService" > nul 2>&1
sc stop "EasyAntiCheat_EOS" > nul 2>&1

sc config "vgc" start= demand > nul 2>&1
sc config "zksvc" start= demand > nul 2>&1
sc config "BEService" start= demand > nul 2>&1
sc config "EasyAntiCheat_EOS" start= demand > nul 2>&1

sc config "wuauserv" start= disabled > nul 2>&1

:: Fechando aplicativos ::

taskkill /F /IM HelpPane.exe > nul 2>&1
taskkill /F /IM SystemSettingsAdminFlows.exe > nul 2>&1

:: Removendo pastas vazias com robocopy ::

robocopy "D:\Documents\League of Legends" "D:\Documents\League of Legends" /S /MOVE > nul 2>&1

:: Executando limpeza de disco ::
@Echo Off
echo.
echo -----------------------------------
echo     Executando Limpeza de Disco
echo -----------------------------------
echo.

cleanmgr.exe /sagerun:1
cleanmgr.exe /verylowdisk /C C,D,E,F,G,H,I,J,K,L,M,N,O,P,Q,R,S,T,U,V,W,X,Y,Z

:: Limpar Cache Nvidia ::
@Echo Off
echo.
echo -----------------------------------
echo         Limpando Cache Nvdia
echo -----------------------------------
echo.

RD /S /Q "GLCache" 
takeown /f "GLCache" /r /d y
takeown /f "C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache" /r /d y
RD /S /Q "C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache"
takeown /f "C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache" /r /d y
del /s /f /q C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache*.*
del /s /f /q GLCache\*.*
rd /s /q C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache
rd /s /q GLCache

takeown /f "GLCache" /r /d y
takeown /f "C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache" /r /d y
RD /S /Q "C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache"
del /s /f /q "C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache\*.*"
RD /S /Q "C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache"
del /q C:\Users\Cowanbas\AppData\Local\NVIDIA\GLCache*.* > nul 2>&1
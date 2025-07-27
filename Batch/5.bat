:: Desinstalando extensões de mídia
echo -- Desinstalando extensões de mídia

:: Remove a extensão de imagem HEIF.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.HEIFImageExtension\" | Remove-AppxPackage"

:: Remove a extensão de vídeo VP9.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.VP9VideoExtensions\" | Remove-AppxPackage"

:: Remove a extensão de imagem WebP.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.WebpImageExtension\" | Remove-AppxPackage"

:: Remove a extensão de vídeo HEVC (H.265).
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.HEVCVideoExtension\" | Remove-AppxPackage"

:: Remove a extensão de imagem RAW.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.RawImageExtension\" | Remove-AppxPackage"

:: Remove as extensões de mídia da Web.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.WebMediaExtensions\" | Remove-AppxPackage"

:: Desinstalando aplicativos de terceiros
echo -- Desinstalando aplicativos de terceiros

:: Remove o jogo Candy Crush Saga.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"king.com.CandyCrushSaga\" | Remove-AppxPackage"

:: Remove o jogo Candy Crush Soda Saga.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"king.com.CandyCrushSodaSaga\" | Remove-AppxPackage"

:: Remove o aplicativo Shazam.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"ShazamEntertainmentLtd.Shazam\" | Remove-AppxPackage"

:: Remove o aplicativo Flipboard.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Flipboard.Flipboard\" | Remove-AppxPackage"

:: Remove o aplicativo Twitter.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"9E2F88E3.Twitter\" | Remove-AppxPackage"

:: Remove o aplicativo iHeartRadio.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"ClearChannelRadioDigital.iHeartRadio\" | Remove-AppxPackage"

:: Remove o aplicativo Duolingo.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"D5EA27B7.Duolingo-LearnLanguagesforFree\" | Remove-AppxPackage"

:: Remove o aplicativo Adobe Photoshop Express.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"AdobeSystemsIncorporated.AdobePhotoshopExpress\" | Remove-AppxPackage"

:: Remove o aplicativo Pandora.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"PandoraMediaInc.29680B314EFC2\" | Remove-AppxPackage"

:: Remove o aplicativo Eclipse Manager.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"46928bounde.EclipseManager\" | Remove-AppxPackage"

:: Remove o aplicativo Actipro Software.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"ActiproSoftwareLLC.562882FEEB491\" | Remove-AppxPackage"

:: Remove o aplicativo Spotify.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"SpotifyAB.SpotifyMusic\" | Remove-AppxPackage"

:: Desabilita a telemetria geral no Visual Studio Code.
echo Desabilitando a telemetria do Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='telemetry.enableTelemetry'; $settingValue=$false; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita o envio de relatórios de falha automáticos no Visual Studio Code.
echo Desabilitando relatórios de falha do Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='telemetry.enableCrashReporter'; $settingValue=$false; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita experimentos online conduzidos pela Microsoft no Visual Studio Code.
echo Desabilitando experimentos online da Microsoft no Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='workbench.enableExperiments'; $settingValue=$false; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita atualizações automáticas do Visual Studio Code, priorizando atualizações manuais.
echo Desabilitando atualizações automáticas no Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='update.mode'; $settingValue='manual'; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita a busca automática de notas de lançamento dos servidores da Microsoft após uma atualização do VS Code.
echo Desabilitando a busca de notas de lançamento no VS Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='update.showReleaseNotes'; $settingValue=$false; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita a verificação automática de atualizações de extensões do serviço online da Microsoft.
echo Desabilitando a verificação automática de extensões no VS Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='extensions.autoCheckUpdates'; $settingValue=$false; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Configura o Visual Studio Code para buscar recomendações de extensões da Microsoft somente sob demanda.
echo Buscando recomendações de extensões apenas sob demanda no VS Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='extensions.showRecommendationsOnlyOnDemand'; $settingValue=$true; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita a busca automática de repositórios remotos no Visual Studio Code.
echo Desabilitando a busca automática de repositórios remotos no VS Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='git.autofetch'; $settingValue=$false; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita a busca de informações de pacotes NPM e Bower online no Visual Studio Code.
echo Desabilitando a busca de informações de pacotes NPM e Bower no VS Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='npm.fetchOnlinePackageInfo'; $settingValue=$false; $jsonFilePath = \"$($env:APPDATA)\Code\User\settings.json\"; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host \"Skipping, no updates. Settings file was not at `\"$jsonFilePath`\" .\"; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw \"Error, failed to read the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host \"Settings file is empty. Treating it as default empty JSON object.\"; $fileContent = \"{}\"; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw \"Error, invalid JSON format in the settings file: `\"$jsonFilePath`\" . Error: $_\"; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host \"Skipping, `\"$settingKey`\" is already configured as `\"$settingValue`\" .\"; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host \"Successfully applied the setting to the file: `\"$jsonFilePath`\" .\";"

:: Desabilita a telemetria (SQM) para várias versões do Visual Studio (32-bit e 64-bit).
echo Desabilitando a telemetria do Visual Studio (SQM).
if %PROCESSOR_ARCHITECTURE%==x86 ( REM is 32 bit?
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
) else (
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
)

:: Desabilita a telemetria (SQM) para o Visual Studio via política de máquina.
reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f

:: Desabilita a telemetria geral do Visual Studio para o usuário atual.
echo Desabilitando a telemetria do Visual Studio.
reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f

:: Desabilita a caixa de diálogo de feedback do Visual Studio.
echo Desabilitando o feedback do Visual Studio.
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d 1 /f

:: Desabilita a entrada de e-mail na caixa de diálogo de feedback do Visual Studio.
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d 1 /f

:: Desabilita a captura de tela na caixa de diálogo de feedback do Visual Studio.
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d 1 /f

:: Para e desabilita o serviço "Visual Studio Standard Collector Service".
echo Parando e desabilitando o serviço "Visual Studio Standard Collector Service".
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'VSStandardCollectorService150'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita a coleta de logs do Diagnostics Hub.
echo Desabilitando a coleta de logs do Diagnostics Hub.
reg delete "HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub" /v "LogLevel" /f 2>nul

:: Desabilita a participação na coleta de dados do IntelliCode (análise remota).
echo Desabilitando a participação na coleta de dados do IntelliCode.
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode" /v "DisableRemoteAnalysis" /d 1 /f

:: Desabilita a análise remota do IntelliCode para o usuário atual (VS 16.0).
reg add "HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode" /v "DisableRemoteAnalysis" /d 1 /f

:: Desabilita a análise remota do IntelliCode para o usuário atual (VS 17.0).
reg add "HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode" /v "DisableRemoteAnalysis" /d 1 /f

:: Limpa dados de telemetria de uso offline do Visual Studio (SQM).
echo Limpando dados de telemetria de uso offline do Visual Studio.
rmdir /s /q %LOCALAPPDATA%\Microsoft\VSCommon\14.0\SQM
rmdir /s /q %LOCALAPPDATA%\Microsoft\VSCommon\15.0\SQM
rmdir /s /q %LOCALAPPDATA%\Microsoft\VSCommon\16.0\SQM
rmdir /s /q %LOCALAPPDATA%\Microsoft\VSCommon\17.0\SQM

:: Limpa logs do Visual Studio Application Insights.
echo Limpando logs do Visual Studio Application Insights.
rmdir /s /q "%LOCALAPPDATA%\Microsoft\VSApplicationInsights" 2>nul
rmdir /s /q "%ProgramData%\Microsoft\VSApplicationInsights" 2>nul
rmdir /s /q "%Temp%\Microsoft\VSApplicationInsights" 2>nul

:: Limpa dados de telemetria do Visual Studio.
echo Limpando dados de telemetria do Visual Studio.
rmdir /s /q "%AppData%\vstelemetry" 2>nul
rmdir /s /q "%ProgramData%\vstelemetry" 2>nul

:: Limpa dados temporários de telemetria e log do Visual Studio.
echo Limpando dados temporários de telemetria e log do Visual Studio.
rmdir /s /q "%Temp%\VSFaultInfo" 2>nul
rmdir /s /q "%Temp%\VSFeedbackPerfWatsonData" 2>nul
rmdir /s /q "%Temp%\VSFeedbackVSRTCLogs" 2>nul
rmdir /s /q "%Temp%\VSFeedbackIntelliCodeLogs" 2>nul
rmdir /s /q "%Temp%\VSRemoteControl" 2>nul
rmdir /s /q "%Temp%\Microsoft\VSFeedbackCollector" 2>nul
rmdir /s /q "%Temp%\VSTelem" 2>nul
rmdir /s /q "%Temp%\VSTelem.Out" 2>nul

:: Remove a entrada do atalho do OneDrive do menu Iniciar.
echo Removendo entrada de atalho do OneDrive.
del "%appdata%\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

:: Remove as tarefas agendadas relacionadas ao OneDrive.
echo Removendo tarefas agendadas do OneDrive.
powershell -Command "Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false"

:: Remove arquivos e pastas residuais do OneDrive.
echo Removendo restos do OneDrive.
rd "%UserProfile%\OneDrive" /Q /S
rd "%LocalAppData%\OneDrive" /Q /S
rd "%LocalAppData%\Microsoft\OneDrive" /Q /S
rd "%ProgramData%\Microsoft OneDrive" /Q /S
rd "C:\OneDriveTemp" /Q /S

:: Exclui a chave de registro do OneDrive para o usuário atual.
reg delete "HKEY_CURRENT_USER\Software\Microsoft\OneDrive" /f

:: Remove o OneDrive da barra lateral do Explorador de Arquivos (para arquiteturas de 64-bit e 32-bit).
echo Removendo OneDrive da barra lateral do explorador.
reg delete "HKEY_CLASSES_ROOT\WOW6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f

:: Limpa chaves de licença do Visual Studio 2010.
echo Limpando licenças do Visual Studio 2010.
reg delete "HKCR\Licenses\77550D6B-6352-4E77-9DA3-537419DF564B" /va /f

:: Limpa chaves de licença do Visual Studio 2015.
echo Limpando licenças do Visual Studio 2015.
reg delete "HKCR\Licenses\4D8CFBCB-2F6A-4AD2-BABF-10E28F6F2C8F" /va /f

:: Limpa chaves de licença do Visual Studio 2017.
echo Limpando licenças do Visual Studio 5C505A59-E312-4B89-9508-E162F8150517.
reg delete "HKCR\Licenses\5C505A59-E312-4B89-9508-E162F8150517" /va /f

:: Limpa chaves de licença do Visual Studio 2019.
echo Limpando licenças do Visual Studio 2019.
reg delete "HKCR\Licenses\41717607-F34E-432C-A138-A3CFD7E25CDA" /va /f

:: Limpa chaves de licença do Visual Studio 2022.
echo Limpando licenças do Visual Studio 2022.
reg delete "HKCR\Licenses\B16F0CF0-8AD1-4A5B-87BC-CB0DBE9C48FC" /va /f
reg delete "HKCR\Licenses\10D17DBA-761D-4CD8-A627-984E75A58700" /va /f
reg delete "HKCR\Licenses\1299B4B9-DFCC-476D-98F0-F65A2B46C96D" /va /f

:: Limpa a lista de arquivos acessados recentemente.
echo Limpando lista de arquivos acessados recentemente.
del /f /q "%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\*"

:: Limpa os itens fixados pelo usuário.
echo Limpando itens fixados para o usuário.
del /f /q "%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\*"

:: Limpa a última chave visitada no Regedit.
echo Limpando a última chave do Regedit.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit" /va /f

:: Limpa as chaves favoritas salvas no Regedit.
echo Limpando chaves favoritas no Regedit.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Regedit\Favorites" /va /f

:: Limpa a lista de aplicativos abertos recentemente.
echo Limpando a lista de aplicativos abertos recentemente.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy" /va /f

:: Limpa a lista de itens usados recentemente (MRU) do "Adobe Media Browser".
echo Limpando a lista MRU do "Adobe Media Browser".
reg delete "HKCU\Software\Adobe\MediaBrowser\MRU" /va /f

:: Limpa a lista de arquivos usados recentemente (MRU) do "MSPaint".
echo Limpando a lista MRU do "MSPaint".
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Paint\Recent File List" /va /f

:: Limpa a lista de arquivos usados recentemente (MRU) do "Wordpad".
echo Limpando a lista MRU do "Wordpad".
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Applets\Wordpad\Recent File List" /va /f

:: Limpa a lista de unidades de rede mapeadas recentemente (MRU).
echo Limpando a lista MRU de "Mapear Unidade de Rede".
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU" /va /f

:: Limpa o histórico do "Assistente de Pesquisa do Windows".
echo Limpando o histórico do "Assistente de Pesquisa do Windows".
reg delete "HKCU\Software\Microsoft\Search Assistant\ACMru" /va /f

:: Limpa a lista de arquivos abertos recentemente para cada tipo de arquivo.
echo Limpando a lista de arquivos abertos recentemente por tipo de arquivo.
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /va /f
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU" /va /f

:: Limpa os arquivos e URLs recentes do Windows Media Player.
echo Limpando arquivos e URLs recentes do Windows Media Player.
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentFileList" /va /f
reg delete "HKCU\Software\Microsoft\MediaPlayer\Player\RecentURLList" /va /f

:: Limpa a lista de arquivos recentes do Windows Media Player para todos os usuários (chave de máquina).
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentFileList" /va /f

:: Limpa a lista de URLs recentes do Windows Media Player para todos os usuários (chave de máquina).
reg delete "HKLM\SOFTWARE\Microsoft\MediaPlayer\Player\RecentURLList" /va /f

:: Limpa o histórico de aplicativos DirectX usados recentemente pelo usuário atual.
echo Limpando o uso recente de aplicativos DirectX.
reg delete "HKCU\Software\Microsoft\Direct3D\MostRecentApplication" /va /f

:: Limpa o histórico de aplicativos DirectX usados recentemente para todos os usuários.
reg delete "HKLM\SOFTWARE\Microsoft\Direct3D\MostRecentApplication" /va /f

:: Limpa a lista de comandos e caminhos digitados recentemente na caixa de diálogo "Executar" do Windows.
echo Limpando a lista de usados recentemente da caixa "Executar" do Windows e caminhos digitados.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" /va /f

:: Limpa o índice de pesquisa do Listary.
echo Limpando o índice de pesquisa do Listary.
del /f /s /q %appdata%\Listary\UserData > nul

:: Limpa o cache do Java.
echo Limpando o cache do Java.
rd /s /q "%APPDATA%\Sun\Java\Deployment\cache"

:: Limpa rastros e dados do Flash Player.
echo Limpando rastros do Flash Player.
rd /s /q "%APPDATA%\Macromedia\Flash Player"

:: Limpa arquivos de despejo, logs e rastros do Steam.
echo Limpando despejos, logs e rastros do Steam.
del /f /q %ProgramFiles(x86)%\Steam\Dumps
del /f /q %ProgramFiles(x86)%\Steam\Traces
del /f /q %ProgramFiles(x86)%\Steam\appcache\*.log

:: Limpa os dados de telemetria da Dotnet CLI.
echo Limpando a telemetria da Dotnet CLI.
rmdir /s /q "%USERPROFILE%\.dotnet\TelemetryStorageService" 2>nul

:: Limpa o cache do Internet Explorer.
echo Limpando o cache do Internet Explorer.
del /f /q "%LOCALAPPDATA%\Microsoft\Windows\INetCache\IE\*"
rd /s /q "%LOCALAPPDATA%\Microsoft\Windows\WebCache"

:: Limpa o histórico de URLs digitadas recentemente no Internet Explorer.
echo Limpando URLs recentes do Internet Explorer.
reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLs" /va /f
reg delete "HKCU\SOFTWARE\Microsoft\Internet Explorer\TypedURLsTime" /va /f

:: Limpa os "Arquivos de Internet Temporários" (cache do navegador).
echo Limpando "Arquivos de Internet Temporários" (cache do navegador).
rd /s /q %userprofile%\Local Settings\Temporary Internet Files
rd /s /q "%LOCALAPPDATA%\Microsoft\Windows\Temporary Internet Files"
takeown /f "%LOCALAPDATA%\Temporary Internet Files" /r /d y
icacls "%LOCALAPPDATA%\Temporary Internet Files" /grant administrators:F /t
rd /s /q "%LOCALAPPDATA%\Temporary Internet Files"
rd /s /q "%LOCALAPPDATA%\Microsoft\Windows\INetCache"

:: Limpa o cache de feeds do Internet Explorer.
echo Limpando o cache de feeds do Internet Explorer.
rd /s /q "%LOCALAPPDATA%\Microsoft\Feeds Cache"

:: Limpa os cookies do Internet Explorer.
echo Limpando os cookies do Internet Explorer.
rd /s /q "%APPDATA%\Microsoft\Windows\Cookies"
rd /s /q "%LOCALAPPDATA%\Microsoft\Windows\INetCookies"

:: Limpa o DOMStore do Internet Explorer (armazenamento de dados web).
echo Limpando o DOMStore do Internet Explorer.
rd /s /q "%LOCALAPPDATA%\Microsoft\InternetExplorer\DOMStore"

:: Limpa dados de uso diversos do Internet Explorer.
echo Limpando dados de uso do Internet Explorer.
rd /s /q "%LOCALAPPDATA%\Microsoft\Internet Explorer"

:: Limpa relatórios de falhas do Google Chrome.
echo Limpando relatórios de falhas do Chrome.
rd /s /q "%LOCALAPPDATA%\Google\Chrome\User Data\Crashpad\reports\"
rd /s /q "%LOCALAPPDATA%\Google\CrashReports\"

:: Limpa logs da Ferramenta de Relatório de Software do Chrome.
echo Limpando logs da Ferramenta de Relatório de Software.
del /f /q "%LOCALAPPDATA%\Google\Software Reporter Tool\*.log"

:: Limpa dados de usuário do Google Chrome.
echo Limpando dados de usuário do Chrome.
rd /s /q "%USERPROFILE%\Local Settings\Application Data\Google\Chrome\User Data"
rd /s /q "%LOCALAPPDATA%\Google\Chrome\User Data"

:: Limpa o histórico de navegação e o cache do Firefox.
echo Limpando histórico de navegação e cache do Firefox.
set ignoreFiles="content-prefs.sqlite" "permissions.sqlite" "favicons.sqlite"
for %%d in ("%APPDATA%\Mozilla\Firefox\Profiles\"
            "%USERPROFILE%\Local Settings\Application Data\Mozilla\Firefox\Profiles\"
        ) do (
    IF EXIST %%d (
        FOR /d %%p IN (%%d*) DO (
            for /f "delims=" %%f in ('dir /b /s "%%p\*.sqlite" 2^>nul') do (
                set "continue="
                for %%i in (%ignoreFiles%) do (
                    if %%i == "%%~nxf" (
                        set continue=1
                    )
                )
                if not defined continue (
                    del /q /s /f %%f
                )
            )
        )
    )
)

:: Limpa perfis de usuário, configurações e dados do Firefox.
echo Limpando perfis, configurações e dados do Firefox.
rd /s /q "%LOCALAPPDATA%\Mozilla\Firefox\Profiles"
rd /s /q "%APPDATA%\Mozilla\Firefox\Profiles"

:: Limpa os ícones de páginas web do Safari.
echo Limpando ícones de páginas web do Safari.
del /q /s /f "%USERPROFILE%\Local Settings\Application Data\Safari\WebpageIcons.db"
del /q /s /f "%LOCALAPDATA%\Apple Computer\Safari\WebpageIcons.db"

:: Limpa o cache do Safari.
echo Limpando o cache do Safari.
del /q /s /f "%USERPROFILE%\Local Settings\Application Data\Apple Computer\Safari\Cache.db"
del /q /s /f "%LOCALAPPDATA%\Apple Computer\Safari\Cache.db"

:: Limpa os cookies do Safari.
echo Limpando os cookies do Safari.
del /q /s /f "%USERPROFILE%\Local Settings\Application Data\Apple Computer\Safari\Cookies.db"
del /q /s /f "%LOCALAPPDATA%\Apple Computer\Safari\Cookies.db"

:: Limpa todos os dados do Safari (perfis de usuário, configurações e dados).
echo Limpando todos os dados do Safari.
rd /s /q "%USERPROFILE%\Local Settings\Application Data\Apple Computer\Safari"
rd /s /q "%AppData%\Apple Computer\Safari"

:: Limpa o histórico do Opera (perfis de usuário, configurações e dados).
echo Limpando histórico do Opera (perfis, configurações e dados).
rd /s /q "%USERPROFILE%\Local Settings\Application Data\Opera\Opera"
rd /s /q "%LOCALAPPDATA%\Opera\Opera"
rd /s /q "%APPDATA%\Opera\Opera"

:: Limpa a pasta temporária do sistema.
echo Limpando a pasta temporária do sistema.
del /s /f /q "%WINDIR%\Temp\*"

:: Limpa a pasta temporária do usuário.
echo Limpando a pasta temporária do usuário.
del /s /f /q "%TEMP%\*"

:: Limpa a pasta de prefetch.
echo Limpando a pasta de prefetch.
del /s /f /q "%WINDIR%\Prefetch\*"

:: Limpa logs de atualização do Windows e de varreduras SFC.
echo Limpando logs de atualização do Windows e SFC.
del /f /q %SystemRoot%\Temp\CBS\*

:: Limpa logs do Serviço de Medicamento de Atualização do Windows (WaasMedic).
echo Limpando logs do Serviço de Medicamento de Atualização do Windows.
takeown /f %SystemRoot%\Logs\waasmedic /r /d y
icacls %SystemRoot%\Logs\waasmedic /grant administrators:F /t
rd /s /q %SystemRoot%\Logs\waasmedic

:: Limpa rastros de diagnóstico dos Serviços Criptográficos.
echo Limpando rastros de diagnóstico dos Serviços Criptográficos.
del /f /q %SystemRoot%\System32\catroot2\dberr.txt
del /f /q %SystemRoot%\System32\catroot2.log
del /f /q %SystemRoot%\System32\catroot2.jrs
del /f /q %SystemRoot%\System32\catroot2.edb
del /f /q %SystemRoot%\System32\catroot2.chk

:: Limpa logs de eventos do Windows Update.
echo Limpando logs de eventos do Windows Update.
del /f /q "%SystemRoot%\Logs\SIH\*"

:: Limpa logs do Windows Update.
echo Limpando logs do Windows Update.
del /f /q "%SystemRoot%\Traces\WindowsUpdate\*"

:: Limpa logs do Gerenciador de Componentes Opcionais e componentes COM+.
echo Limpando logs do Gerenciador de Componentes Opcionais e COM+.
del /f /q %SystemRoot%\comsetup.log

:: Limpa logs do Coordenador de Transações Distribuídas (Dtc).
echo Limpando logs do Coordenador de Transações Distribuídas (Dtc).
del /f /q %SystemRoot%\DtcInstall.log

:: Limpa logs para operações de renomeação de arquivos pendentes/sem sucesso.
echo Limpando logs de operações de renomeação de arquivos.
del /f /q %SystemRoot%\PFRO.log

:: Limpa logs de instalação de atualização do Windows.
echo Limpando logs de instalação de atualização do Windows.
del /f /q %SystemRoot%\setupact.log
del /f /q %SystemRoot%\setuperr.log

:: Limpa logs de configuração do Windows.
echo Limpando logs de configuração do Windows.
del /f /q %SystemRoot%\setupapi.log
del /f /q %SystemRoot%\Panther\*
del /f /q %SystemRoot%\inf\setupapi.app.log
del /f /q %SystemRoot%\inf\setupapi.dev.log
del /f /q %SystemRoot%\inf\setupapi.offline.log

:: Limpa logs da Ferramenta de Avaliação do Sistema Windows (WinSAT).
echo Limpando logs do WinSAT.
del /f /q %SystemRoot%\Performance\WinSAT\winsat.log

:: Limpa logs de eventos de mudança de senha.
echo Limpando logs de eventos de mudança de senha.
del /f /q %SystemRoot%\debug\PASSWD.LOG

:: Limpa o banco de dados de cache da web do usuário.
echo Limpando o banco de dados de cache da web do usuário.
del /f /q %LOCALAPPDATA%\Microsoft\Windows\WebCache\*.*

:: Limpa a pasta temporária do sistema quando não há sessão de usuário.
echo Limpando a pasta temporária do sistema sem login.
del /f /q %SystemRoot%\ServiceProfiles\LocalService\AppData\Local\Temp\*.*

:: Limpa logs do DISM (Deployment Image Servicing and Management).
echo Limpando logs do DISM.
del /f /q %SystemRoot%\Logs\CBS\CBS.log
del /f /q %SystemRoot%\Logs\DISM\DISM.log

:: Limpa logs do Histórico de Atualizações do Windows (WUAgent).
echo Limpando logs do Histórico de Atualizações do Windows (WUAgent).
setlocal EnableDelayedExpansion
    SET /A wuau_service_running=0
    SC queryex "wuauserv"|Find "STATE"|Find /v "RUNNING">Nul||(
        SET /A wuau_service_running=1
        net stop wuauserv
    )
    del /q /s /f "%SystemRoot%\SoftwareDistribution"
    IF !wuau_service_running! == 1 (
        net start wuauserv
    )
endlocal

:: Limpa logs de eventos do sistema gerados pelo "Server-initiated Healing Events".
echo Limpando logs de eventos do sistema "Server-initiated Healing Events".
del /f /q "%SystemRoot%\Logs\SIH\*"

:: Limpa rastros de uso do Common Language Runtime (CLR) para .NET Framework.
echo Limpando logs do Common Language Runtime.
del /f /q "%LOCALAPPDATA%\Microsoft\CLR_v4.0\UsageTraces\*"
del /f /q "%LOCALAPPDATA%\Microsoft\CLR_v4.0_32\UsageTraces\*"

:: Limpa logs de eventos do sistema do Serviço de Configuração de Rede.
echo Limpando logs de eventos do Serviço de Configuração de Rede.
del /f /q "%SystemRoot%\Logs\NetSetup\*"

:: Limpa logs gerados pela Ferramenta de Limpeza de Disco (cleanmgr.exe).
echo Limpando logs gerados pela Ferramenta de Limpeza de Disco.
del /f /q "%SystemRoot%\System32\LogFiles\setupcln\*"

:: Limpa o cache de miniaturas de arquivos.
echo Limpando o cache de miniaturas.
del /f /s /q /a %LOCALAPPDATA%\Microsoft\Windows\Explorer\*.db

:: Limpa o arquivo primário de telemetria do Windows.
echo Limpando o arquivo primário de telemetria do Windows.
if exist "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" (
    takeown /f "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /r /d y
    icacls "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl" /grant administrators:F /t
    echo "" > "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
    echo Limpeza bem-sucedida: "%ProgramData%\Microsoft\Diagnosis\ETLLogs\AutoLogger\AutoLogger-Diagtrack-Listener.etl"
) else (
    echo "O arquivo principal de telemetria não existe. Ótimo!"
)

:: Limpa todos os logs de eventos no Visualizador de Eventos.
echo Limpando logs de eventos no Visualizador de Eventos.
REM https://social.technet.microsoft.com/Forums/en-US/f6788f7d-7d04-41f1-a64e-3af9f700e4bd/failed-to-clear-log-microsoftwindowsliveidoperational-access-is-denied?forum=win10itprogeneral
wevtutil sl Microsoft-Windows-LiveId/Operational /ca:O:BAG:SYD:(A;;0x1;;;SY)(A;;0x5;;;BA)(A;;0x1;;;LA)
for /f "tokens=*" %%i in ('wevtutil.exe el') DO (
    echo Excluindo log de eventos: "%%i"
    wevtutil.exe cl %1 "%%i"
)

:: Limpa o histórico de verificação (proteção) do Windows Defender.
echo Limpando histórico de verificação do Defender.
PowerShell -ExecutionPolicy Unrestricted -Command "$command = 'del \"^""%ProgramData%\Microsoft\Windows Defender\Scans\History^"" /s /f /q'; $trustedInstallerSid = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'); $trustedInstallerName = $trustedInstallerSid.Translate([System.Security.Principal.NTAccount]); $streamOutFile = New-TemporaryFile; $batchFile = New-TemporaryFile; try {; $batchFile = Rename-Item $batchFile \"^""$($batchFile.BaseName).bat^"" -PassThru; \"^""@echo off`r`n$command`r`nexit 0^"" | Out-File $batchFile -Encoding ASCII; $taskName = 'privacy.sexy invoke'; schtasks.exe /delete /tn \"^""$taskName^"" /f 2>&1 | Out-Null <# Clean if something went wrong before, suppress any output #>; $taskAction = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument \"^""cmd /c `\"^""$batchFile`\"^"" > $streamOutFile 2>&1^""; $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries; Register-ScheduledTask -TaskName $taskName -Action $taskAction -Settings $settings -Force -ErrorAction Stop | Out-Null; try {; ($scheduleService = New-Object -ComObject Schedule.Service).Connect(); $scheduleService.GetFolder('\').GetTask($taskName).RunEx($null, 0, 0, $trustedInstallerName) | Out-Null; $timeOutLimit = (Get-Date).AddMinutes(5); Write-Host \"^""Running as $trustedInstallerName^""; while((Get-ScheduledTaskInfo $taskName).LastTaskResult -eq 267009) {; Start-Sleep -Milliseconds 200; if((Get-Date) -gt $timeOutLimit) {; Write-Warning \"^""Skipping results, it took so long to execute script.^""; break;; }; }; if (($result = (Get-ScheduledTaskInfo $taskName).LastTaskResult) -ne 0) {; Write-Error \"^""Failed to execute with exit code: $result.^""; }; } finally {; schtasks.exe /delete /tn \"^""$taskName^"" /f | Out-Null <# Outputs only errors #>; }; Get-Content $streamOutFile; } finally {; Remove-Item $streamOutFile, $batchFile; }"

:: Limpa as credenciais armazenadas no Gerenciador de Credenciais do Windows.
echo Limpando credenciais no Gerenciador de Credenciais do Windows.
cmdkey.exe /list > "%TEMP%\List.txt"
findstr.exe Target "%TEMP%\tokensonly.txt"
FOR /F "tokens=1,2 delims= " %%G IN (%TEMP%\tokensonly.txt) DO cmdkey.exe /delete:%%H
del "%TEMP%\List.txt" /s /f /q
del "%TEMP%\tokensonly.txt" /s /f /q

:: Remove o usuário controverso 'defaultuser0'.
echo Removendo o usuário 'defaultuser0'.
net user defaultuser0 /delete 2>nul

:: Minimiza os dados de atualização "Reset Base" do DISM.
echo Minimizando dados de atualização DISM "Reset Base".
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SideBySide\Configuration" /v "DisableResetbase" /t "REG_DWORD" /d "0" /f

:: Remove a chave do produto Windows do registro.
echo Removendo a chave do produto Windows do registro.
cscript.exe //nologo "%SystemRoot%\system32\slmgr.vbs" /cpky

:: Remove associações de aplicativos padrão.
echo Removendo associações de aplicativos padrão.
dism /online /Remove-DefaultAppAssociations

:: Desinstala vários componentes do Xbox.
echo Desinstalando Xbox.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.XboxApp\" | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.Xbox.TCUI\" | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.XboxGamingOverlay\" | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.XboxGameOverlay\" | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.XboxIdentityProvider\" | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.XboxSpeechToTextOverlay\" | Remove-AppxPackage"
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.GamingApp\" | Remove-AppxPackage"

:: Adiciona chaves de registro para desprovisionar os pacotes do Xbox removidos para todos os usuários.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxSpeechToTextOverlay_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.Xbox.TCUI_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxApp_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxGamingOverlay_8wekyb3d8bbwe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\Microsoft.XboxGameOverlay_8wekyb3d8bbwe" /f

:: Limpa dados do Monitor de Uso de Recursos do Sistema (SRUM).
echo Limpando dados do Monitor de Uso de Recursos do Sistema (SRUM).
PowerShell -ExecutionPolicy Unrestricted -Command "$srumDatabaseFilePath = \"$env:WINDIR\System32\sru\SRUDB.dat\"; if (!(Test-Path -Path $srumDatabaseFilePath)) {; Write-Output \"Skipping, SRUM database file not found at `\"$srumDatabaseFilePath`\" . No actions are required.\"; exit 0; }; $dps = Get-Service -Name 'DPS' -ErrorAction Ignore; $isDpsInitiallyRunning = $false; if ($dps) {; $isDpsInitiallyRunning = $dps.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running; if ($isDpsInitiallyRunning) {; Write-Output \"Stopping the Diagnostic Policy Service (DPS) to delete the SRUM database file.\"; $dps | Stop-Service -Force; $dps.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped); Write-Output \"Successfully stopped Diagnostic Policy Service (DPS).\"; }; } else {; Write-Output \"Diagnostic Policy Service (DPS) not found. Proceeding without stopping the service.\"; }; try {; Remove-Item -Path $srumDatabaseFilePath -Force -ErrorAction Stop; Write-Output \"Successfully deleted the SRUM database file at `\"$srumDatabaseFilePath`\" .\"; } catch {; throw \"Failed to delete SRUM database file at: `\"$srumDatabaseFilePath`\" . Error Details: $($_.Exception.Message)\"; } finally {; if ($isDpsInitiallyRunning) {; try {; if ((Get-Service -Name 'DPS').Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Output \"Restarting the Diagnostic Policy Service (DPS).\"; $dps | Start-Service; }; } catch {; throw \"Failed to restart the Diagnostic Policy Service (DPS). Error Details: $($_.Exception.Message)\"; }; }; }"

:: Desabilita o recurso "Assistente de Compatibilidade de Programas (PCA)".
echo Desabilitando o recurso "Assistente de Compatibilidade de Programas (PCA)".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisablePCA" /t REG_DWORD /d 1 /f

:: Para e desabilita o serviço "Assistente de Compatibilidade de Programas" (PcaSvc).
echo Desabilitando o serviço "Assistente de Compatibilidade de Programas" (PcaSvc).
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'PcaSvc'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita a Telemetria de Impacto de Aplicativos (AIT).
echo Desabilitando a Telemetria de Impacto de Aplicativos (AIT).
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f

:: Desabilita o Mecanismo de Compatibilidade de Aplicativos.
echo Desabilitando o Mecanismo de Compatibilidade de Aplicativos.
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisableEngine" /t REG_DWORD /d "1" /f

:: Remove a aba "Compatibilidade de Programa" das propriedades de arquivo.
echo Removendo a aba "Compatibilidade de Programa" das propriedades de arquivo.
reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "DisablePropPage" /t REG_DWORD /d "1" /f

:: Desabilita o Gravador de Passos (coleta capturas de tela, entrada de mouse/teclado e dados de UI).
echo Desabilitando o Gravador de Passos.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f

:: Desabilita a tarefa "Coletor de Inventário".
echo Desabilitando a tarefa "Coletor de Inventário".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f

:: Para e desabilita o serviço "Experiências de Usuário Conectadas e Telemetria" (DiagTrack).
echo Desabilitando o serviço "Experiências de Usuário Conectadas e Telemetria" (DiagTrack).
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'DiagTrack'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita o serviço de roteamento de notificação push WAP.
echo Desabilitando o serviço de roteamento de notificação push WAP.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dmwappushservice'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita o serviço "Diagnostics Hub Standard Collector".
echo Desabilitando o serviço "Diagnostics Hub Standard Collector".
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'diagnosticshub.standardcollector.service'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita o serviço "Diagnostic Execution Service" (diagsvc).
echo Desabilitando o serviço "Diagnostic Execution Service" (diagsvc).
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'diagsvc'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita a tarefa de telemetria `devicecensus.exe`.
echo Desabilitando a tarefa `devicecensus.exe` (telemetria).
schtasks /change /TN "Microsoft\Windows\Device Information\Device" /disable

:: Desabilita o processo `devicecensus.exe` (telemetria) redirecionando-o para `taskkill.exe`.
echo Desabilitando o processo `devicecensus.exe` (telemetria).
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'DeviceCensus.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

:: Desabilita a tarefa "Microsoft Compatibility Appraiser".
echo Desabilitando a tarefa "Microsoft Compatibility Appraiser".
schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable

:: Desabilita o processo `CompatTelRunner.exe` (Microsoft Compatibility Appraiser) redirecionando-o para `taskkill.exe`.
echo Desabilitando o processo `CompatTelRunner.exe` (Microsoft Compatibility Appraiser).
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'CompatTelRunner.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f

:: Desabilita o envio de informações para o Programa de Aprimoramento da Experiência do Cliente.
echo Desabilitando o envio de informações para o Programa de Aprimoramento da Experiência do Cliente.
schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable

:: Desabilita a tarefa "Application Impact Telemetry Agent".
echo Desabilitando a tarefa "Application Impact Telemetry Agent".
schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable

:: Desabilita o lembrete para "Desabilitar aplicativos para melhorar o desempenho".
echo Desabilitando o lembrete para "Desabilitar aplicativos para melhorar o desempenho".
schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable

:: Desabilita o processamento de Desktop Analytics.
echo Desabilitando o processamento de Desktop Analytics.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d 0 /f

:: Desabilita o envio do nome do dispositivo nos dados de diagnóstico do Windows.
echo Desabilitando o envio do nome do dispositivo nos dados de diagnóstico do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f

:: Desabilita a coleta de dados de navegação do Edge para Desktop Analytics.
echo Desabilitando a coleta de dados de navegação do Edge para Desktop Analytics.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d 0 /f

:: Desabilita o processamento de dados de diagnóstico para a nuvem de negócios.
echo Desabilitando o processamento de dados de diagnóstico para a nuvem de negócios.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowWUfBCloudProcessing" /t REG_DWORD /d 0 /f

:: Desabilita o processamento de dados de diagnóstico do Update Compliance.
echo Desabilitando o processamento de dados de diagnóstico do Update Compliance.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowUpdateComplianceProcessing" /t REG_DWORD /d 0 /f

:: Desabilita o uso comercial de dados coletados.
echo Desabilitando o uso comercial de dados coletados.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d 0 /f

:: Desabilita o Programa de Aprimoramento da Experiência do Cliente (CEIP).
echo Desabilitando o Programa de Aprimoramento da Experiência do Cliente (CEIP).
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f

:: Desabilita tarefas agendadas do Programa de Aprimoramento da Experiência do Cliente.
echo Desabilitando tarefas do Programa de Aprimoramento da Experiência do Cliente.
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE

:: Desabilita a telemetria de diagnóstico e uso (usando preferência de política local e objeto de política de grupo).
echo Desabilitando a telemetria de diagnóstico e uso.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

:: Desabilita downloads automáticos de configuração da nuvem (OneSettings).
echo Desabilitando downloads automáticos de configuração da nuvem.
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableOneSettingsDownloads" /t "REG_DWORD" /d "1" /f

:: Desabilita a telemetria de licenças (Software Protection Platform).
echo Desabilitando a telemetria de licenças.
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f

:: Desabilita o Relatório de Erros do Windows e serviços relacionados.
echo Desabilitando o Relatório de Erros do Windows.
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wersvc'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wercplsupport'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita a recuperação de metadados de dispositivos (pode quebrar atualizações automáticas).
echo Desabilitando a recuperação de metadados de dispositivos.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d 1 /f

:: Desabilita a inclusão de drivers com atualizações do Windows.
echo Desabilitando a inclusão de drivers com atualizações do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d 1 /f

:: Desabilita a pesquisa de drivers de dispositivos do Windows Update.
echo Desabilitando a pesquisa de drivers de dispositivos do Windows Update.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f

:: Desabilita o método de download ponto a ponto para atualizações do Windows (Delivery Optimization).
echo Desabilitando o método de download ponto a ponto para atualizações do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t "REG_DWORD" /d 0 /f

:: Desabilita o serviço "Delivery Optimization" (pode quebrar downloads da Microsoft Store).
echo Desabilitando o serviço "Delivery Optimization".
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceQuery = 'DoSvc'; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceQuery -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service query `\"$serviceQuery`\" did not yield any results, no need to disable it.\"; Exit 0; }; $serviceName = $service.Name; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, trying to stop it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if service info is not found in registry #>; $registryKey = \"HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\"; if(!(Test-Path $registryKey)) {; Write-Host \"`\"$registryKey`\" is not found in registry, cannot enable it.\"; Exit 0; }; <# -- 4. Skip if already disabled #>; if( $(Get-ItemProperty -Path \"$registryKey\").Start -eq 4) {; Write-Host \"`\"$serviceName`\" is already disabled from start, no further action is needed.\"; Exit 0; }; <# -- 5. Disable service #>; try {; Set-ItemProperty $registryKey -Name Start -Value 4 -Force -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita o acesso de aplicativos à pasta "Documentos".
echo Desabilitando o acesso de aplicativos à pasta "Documentos".
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /d "Deny" /t REG_SZ /f

:: Desabilita o acesso de aplicativos à pasta "Imagens".
echo Desabilitando o acesso de aplicativos à pasta "Imagens".
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /d "Deny" /t REG_SZ /f

:: Desabilita o acesso de aplicativos à pasta "Vídeos".
echo Desabilitando o acesso de aplicativos à pasta "Vídeos".
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /d "Deny" /t REG_SZ /f

:: Desabilita o acesso de aplicativos a outros sistemas de arquivos.
echo Desabilitando o acesso de aplicativos a outros sistemas de arquivos.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /d "Deny" /t REG_SZ /f

:: Desabilita a ativação por voz para aplicativos, incluindo a Cortana.
echo Desabilitando a ativação por voz para aplicativos, incluindo a Cortana.
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d 2 /f

:: Desabilita a ativação por voz para aplicativos, incluindo a Cortana, no sistema bloqueado.
echo Desabilitando a ativação por voz para aplicativos no sistema bloqueado.
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d 2 /f

:: Desabilita o acesso de aplicativos à localização.
echo Desabilitando o acesso de aplicativos à localização.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /d "Deny" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /d "0" /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos a informações da conta, nome e foto.
echo Desabilitando o acesso de aplicativos a informações da conta.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos a dados de movimento.
echo Desabilitando o acesso de aplicativos a dados de movimento.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos ao telefone.
echo Desabilitando o acesso de aplicativos ao telefone.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos a dispositivos confiáveis.
echo Desabilitando o acesso de aplicativos a dispositivos confiáveis.
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita a sincronização de aplicativos com dispositivos (não pareados, beacons, TVs, etc.).
echo Desabilitando a sincronização de aplicativos com dispositivos.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o compartilhamento e sincronização de aplicativos para dispositivos sem fio não explicitamente pareados.
echo Desabilitando compartilhamento e sincronização para dispositivos sem fio não pareados.
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /t REG_SZ /v "Value" /d "Deny" /f

:: Desabilita o acesso de aplicativos a informações de diagnóstico sobre outros aplicativos.
echo Desabilitando o acesso de aplicativos a informações de diagnóstico.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos aos seus contatos.
echo Desabilitando o acesso de aplicativos aos contatos.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEEFD62DED93}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos ao Calendário.
echo Desabilitando o acesso de aplicativos ao Calendário.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos ao histórico de chamadas.
echo Desabilitando o acesso de aplicativos ao histórico de chamadas.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos ao e-mail.
echo Desabilitando o acesso de aplicativos ao e-mail.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos a tarefas.
echo Desabilitando o acesso de aplicativos a tarefas.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos a mensagens (SMS / MMS).
echo Desabilitando o acesso de aplicativos a mensagens (SMS / MMS).
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{21157C1F-2651-4CC1-90CA-1F28B02263F6}" /t REG_SZ /v "Value" /d "Deny" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos a rádios.
echo Desabilitando o acesso de aplicativos a rádios.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /d "Deny" /t REG_SZ /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /t REG_SZ /v "Value" /d DENY /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_UserInControlOfTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceAllowTheseApps" /t REG_MULTI_SZ /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceDenyTheseApps" /t REG_MULTI_SZ /f

:: Desabilita o acesso de aplicativos a dispositivos Bluetooth.
echo Desabilitando o acesso de aplicativos a dispositivos Bluetooth.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /d "Deny" /t REG_SZ /f

:: Desabilita o Provedor de Localização do Windows.
echo Desabilitando o Provedor de Localização do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f

:: Desabilita o script de localização.
echo Desabilitando o script de localização.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f

:: Desabilita completamente a localização no Windows.
echo Desabilitando a localização.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f

:: Desabilita a exibição do histórico da Cortana.
echo Desabilitando a exibição do histórico da Cortana.
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f

:: Desabilita o uso do histórico de dispositivos pela Cortana.
echo Desabilitando o uso do histórico de dispositivos pela Cortana.
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f

:: Desabilita a ativação por voz "Hey Cortana".
echo Desabilitando a ativação por voz "Hey Cortana".
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f

:: Desabilita a Cortana de ouvir comandos com Windows key + C.
echo Desabilitando a Cortana de ouvir comandos com Windows key + C.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t REG_DWORD /d 0 /f

:: Desabilita a Cortana no dispositivo bloqueado.
echo Desabilitando a Cortana no dispositivo bloqueado.
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t REG_DWORD /d 0 /f

:: Desabilita a atualização automática de Dados de Fala.
echo Desabilitando a atualização automática de Dados de Fala.
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t REG_DWORD /d 0 /f

:: Desabilita o suporte de voz da Cortana durante a configuração do Windows (OOBE).
echo Desabilitando o suporte de voz da Cortana durante a configuração do Windows.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t REG_DWORD /d 1 /f

:: Desabilita a Cortana na busca.
echo Desabilitando a Cortana na busca.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

:: Desabilita a experiência da Cortana.
echo Desabilitando a experiência da Cortana.
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f

:: Desabilita o acesso da Cortana a serviços de nuvem como OneDrive e SharePoint.
echo Desabilitando o acesso da Cortana a serviços de nuvem.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f

:: Desabilita a interação de fala da Cortana enquanto o sistema está bloqueado.
echo Desabilitando a interação de fala da Cortana com o sistema bloqueado.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f

:: Desabilita a participação na coleta de dados da Cortana.
echo Desabilitando a participação na coleta de dados da Cortana.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f

:: Desabilita a habilitação da Cortana.
echo Desabilitando a habilitação da Cortana.
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t REG_DWORD /d 0 /f

:: Desabilita a Cortana (resultados de busca na internet no menu iniciar).
echo Desabilitando a Cortana (resultados de busca na internet).
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f

:: Remove o ícone da Cortana da barra de tarefas.
echo Removendo o ícone da Cortana da barra de tarefas.
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v "ShowCortanaButton" /t REG_DWORD /d 0 /f

:: Desabilita a Cortana no modo ambiente.
echo Desabilitando a Cortana no modo ambiente.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t REG_DWORD /d 0 /f

:: Desabilita a indexação de itens e armazenamentos criptografados.
echo Desabilitando a indexação de itens e armazenamentos criptografados.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t REG_DWORD /d 0 /f

:: Desabilita a detecção automática de idioma ao indexar.
echo Desabilitando a detecção automática de idioma ao indexar.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t REG_DWORD /d 0 /f

:: Desabilita o acesso da busca à localização.
echo Desabilitando o acesso da busca à localização.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

:: Desabilita a busca na web na barra de pesquisa.
echo Desabilitando a busca na web na barra de pesquisa.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f

:: Desabilita a busca na web e resultados na pesquisa.
echo Desabilitando a busca na web e resultados na pesquisa.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f

:: Desabilita a busca do Bing.
echo Desabilitando a busca do Bing.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f

:: Desabilita as Dicas do Windows.
echo Desabilitando as Dicas do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f

:: Desabilita o Windows Spotlight (mostra papéis de parede aleatórios na tela de bloqueio).
echo Desabilitando o Windows Spotlight.
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f

:: Desabilita as Experiências de Consumidor da Microsoft.
echo Desabilitando as Experiências de Consumidor da Microsoft.
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f

:: Desabilita a personalização de anúncios com o ID de Publicidade.
echo Desabilitando a personalização de anúncios com o ID de Publicidade.
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f

:: Desabilita o conteúdo sugerido no aplicativo Configurações.
echo Desabilitando o conteúdo sugerido no aplicativo Configurações.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f

:: Desabilita o uso de biometria (impressão digital, reconhecimento facial, etc.).
echo Desabilitando o uso de biometria.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desabilita o logon biométrico.
echo Desabilitando o logon biométrico.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f

:: Desinstala o Microsoft Edge usando um script PowerShell externo.
echo Desinstalando o Edge.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$script = (New-Object Net.WebClient).DownloadString('https://cdn.jsdelivr.net/gh/he3als/EdgeRemover@main/get.ps1'); $script = [ScriptBlock]::Create($script); & $script -UninstallEdge"

:: Desabilita o serviço de Biometria do Windows.
echo Desabilitando o serviço de Biometria do Windows.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'WbioSrvc'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita o Serviço Windows Insider.
echo Desabilitando o Serviço Windows Insider.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wisvc'; Write-Host \"Disabling service: `\"$serviceName`\" .\"; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host \"Service `\"$serviceName`\" could not be not found, no need to disable it.\"; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host \"`\"$serviceName`\" is running, stopping it.\"; try {; Stop-Service -Name \"$serviceName\" -Force -ErrorAction Stop; Write-Host \"Stopped `\"$serviceName`\" successfully.\"; } catch {; Write-Warning \"Could not stop `\"$serviceName`\" , it will be stopped after reboot: $_ \"; }; } else {; Write-Host \"`\"$serviceName`\" is not running, no need to stop.\"; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query \"Select StartMode From Win32_Service Where Name='$serviceName'\" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter \"Name='$serviceName'\" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host \"$serviceName is already disabled, no further action is needed\"; }; <# -- 4. Disable service #>; try {; Set-Service -Name \"$serviceName\" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host \"Disabled `\"$serviceName`\" successfully.\"; } catch {; Write-Error \"Could not disable `\"$serviceName`\" : $_ \"; }"

:: Desabilita testes de recursos da Microsoft.
echo Desabilitando testes de recursos da Microsoft.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\System\AllowExperimentation" /v "value" /t "REG_DWORD" /d 0 /f

:: Desabilita o recebimento de builds de pré-visualização do Windows.
echo Desabilitando o recebimento de builds de pré-visualização do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f

:: Remove a seção "Programa Windows Insider" das Configurações.
echo Removendo "Programa Windows Insider" das Configurações.
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility" /v "HideInsiderPage" /t "REG_DWORD" /d "1" /f

:: Desabilita toda a sincronização de configurações.
echo Desabilitando toda a sincronização de configurações.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f

:: Desabilita a sincronização de configurações de "Aplicativos".
echo Desabilitando a sincronização de configurações de "Aplicativos".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f

:: Desabilita a sincronização de configurações de "Sincronização de Aplicativos".
echo Desabilitando a sincronização de configurações de "Sincronização de Aplicativos".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f

:: Desabilita a sincronização de configurações de "Credenciais".
echo Desabilitando a sincronização de configurações de "Credenciais".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f

:: Desabilita a sincronização de configurações de "Tema da Área de Trabalho".
echo Desabilitando a sincronização de configurações de "Tema da Área de Trabalho".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f

:: Desabilita a sincronização de configurações de "Personalização".
echo Desabilitando a sincronização de configurações de "Personalização".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f

:: Desabilita a sincronização de configurações de "Layout do Menu Iniciar".
echo Desabilitando a sincronização de configurações de "Layout do Menu Iniciar".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f

:: Desabilita a sincronização de configurações do "Navegador Web".
echo Desabilitando a sincronização de configurações do "Navegador Web".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f

:: Desabilita a sincronização de configurações do "Windows".
echo Desabilitando a sincronização de configurações do "Windows".
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f

:: Desabilita a sincronização de configurações de "Idioma".
echo Desabilitando a sincronização de configurações de "Idioma".
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /t REG_DWORD /v "Enabled" /d 0 /f

:: Desabilita o reconhecimento de fala baseado em nuvem.
echo Desabilitando o reconhecimento de fala baseado em nuvem.
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t "REG_DWORD" /d 0 /f

:: Desabilita a sondagem ativa para o servidor Microsoft NCSI.
echo Desabilitando a sondagem ativa para o servidor Microsoft NCSI.
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f

:: Desabilita o consentimento de privacidade do Windows.
echo Desabilitando o consentimento de privacidade do Windows.
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f

:: Desabilita a coleta de feedback do Windows.
echo Desabilitando a coleta de feedback do Windows.
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

:: Remove o Microsoft Copilot (assistente de IA).
echo Removendo o Copilot.
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage \"Microsoft.CoPilot\" | Remove-AppxPackage"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "AutoOpenCopilotLargeScreens" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\Shell\Copilot\BingChat" /v "IsUserEligible" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HubsSidebarEnabled" /t "REG_DWORD" /d "0" /f

:: Realiza uma "limpeza" no Microsoft Edge, desabilitando diversas funcionalidades e telemetria.
echo Realizando a limpeza do Edge.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeEnhanceImagesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "HideFirstRunExperience" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "UserFeedbackAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ConfigureDoNotTrack" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "AlternateErrorPagesEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeCollectionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeFollowEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeShoppingAssistantEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MicrosoftEdgeInsiderPromotionEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "RelatedMatchesCloudServiceEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "ShowMicrosoftRewards" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "WebWidgetAllowed" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "StartupBoostEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "BingAdsSuppression" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "NewTabPageHideDefaultTopSites" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "PromotionalTabsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SpotlightExperiencesAndRecommendationsEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "EdgeAssetDeliveryServiceEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "CryptoWalletEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "WalletDonationEnabled" /t REG_DWORD /d 0 /f

:: Desinstala o recurso de Widgets do Windows.
echo Desinstalando os Widgets.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t "REG_DWORD" /d "0" /f
PowerShell -ExecutionPolicy Unrestricted -Command "Get-AppxPackage *WebExperience* | Remove-AppxPackage"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\MicrosoftWindows.Client.WebExperience_cw5n1h2txyewy" /f

:: Desabilita os Widgets da Barra de Tarefas e o botão Visualização de Tarefas.
echo Desabilitando os Widgets da Barra de Tarefas.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\NewsAndInterests\AllowNewsAndInterests" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d 0 /f

:: Desabilita a sincronização de configurações em nuvem do Windows.
echo Desabilitando a sincronização em nuvem.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d 5 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /t REG_DWORD /v "Enabled" /d 0 /f

:: Desabilita o Feed de Atividades do Windows.
echo Desabilitando o Feed de Atividades.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f

:: Desabilita a Bandeja de Notificações e as notificações pop-up (Toast).
echo Desabilitando a Bandeja de Notificações.
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /d "1" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /d "0" /t REG_DWORD /f

:: Desabilita a Gravação de Tela do Xbox (Game DVR).
echo Desabilitando a Gravação de Tela do Xbox.
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

:: Desabilita downloads automáticos de mapas.
echo Desabilitando Downloads Automáticos de Mapas.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f

:: Desabilita a câmera na tela de bloqueio.
echo Desabilitando a Câmera na Tela de Bloqueio.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f

:: Desabilita a biometria (quebra o Windows Hello).
echo Desabilitando a Biometria (quebra o Windows Hello).
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics\Credential Provider" /v "Enabled" /t "REG_DWORD" /d "0" /f

:: Desabilita a telemetria do Windows, incluindo tarefas agendadas, serviços e configurações de registro.
echo Desabilitando a Telemetria do Windows.
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Autochk\Proxy" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /DISABLE > NUL 2>&1
sc config diagnosticshub.standardcollector.service start=demand
sc config diagsvc start=demand
sc config WerSvc start=demand
sc config wercplsupport start=demand
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowWUfBCloudProcessing" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowUpdateComplianceProcessing" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v "DisableOneSettingsDownloads" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /d "0" /t REG_DWORD /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /d "0" /t REG_DWORD /f
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" /v "EnableAccountNotifications" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SystemSettings\AccountNotifications" /v "EnableAccountNotifications" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d "1" /f
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f

:: Desabilita a telemetria de Atualizações do Windows e a otimização de entrega.
echo Desabilitando a Telemetria de Atualizações do Windows.
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t "REG_DWORD" /d 0 /f

:: Desabilita a telemetria da Busca do Windows, histórico de pesquisa e recursos relacionados à web.
echo Desabilitando a Telemetria da Busca do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d "3" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Explorer" /v "DisableSearchHistory" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventUnwantedAddIns" /t "REG_SZ" /d " " /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventRemoteQueries" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AlwaysUseAutoLangDetection" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowIndexingEncryptedStoresOrItems" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DisableSearchBoxSuggestions" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaInAmbientMode" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCortanaButton" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CanCortanaBeEnabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\Experience\AllowCortana" /v "value" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "ModelDownloadAllowed" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDeviceSearchHistoryEnabled" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationOn" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationEnableAboveLockscreen" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "DisableVoice" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\Speech_OneCore\Preferences" /v "VoiceActivationDefaultOn" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsMSACloudSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsAADCloudSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t "REG_DWORD" /d "0" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "VoiceShortcut" /t "REG_DWORD" /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t "REG_DWORD" /d "0" /f

:: Desabilita a telemetria do Microsoft Office, incluindo log de e-mails, calendários e documentos, e serviços de feedback.
echo Desabilitando a Telemetria do Office.
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE > NUL 2>&1
schtasks /change /TN "\Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE > NUL 2>&1

:: Desabilita a telemetria da Experiência de Aplicativos do Windows.
echo Desabilitando a Telemetria da Experiência de Aplicativos.
schtasks /change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser Exp" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Application Experience\PcaPatchDbTask" /DISABLE
schtasks /change /TN "\Microsoft\Windows\Application Experience\MareBackup" /DISABLE

:: Desabilita a telemetria da Experiência de Feedback do Windows, incluindo notificações.
echo Desabilitando a Telemetria da Experiência de Feedback do Windows.
reg add "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

:: Desabilita a telemetria de escrita à mão (Handwriting) e coleta de dados de personalização de entrada.
echo Desabilitando a Telemetria de Escrita à Mão.
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

:: Desabilita o acesso à internet para o Gerenciamento de Direitos Digitais (DRM) do Windows.
echo Desabilitando o Acesso à Internet para o DRM do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f

:: Desabilita o reconhecimento de fala baseado em nuvem.
echo Desabilitando o Reconhecimento de Fala Baseado em Nuvem.
reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f

:: Desabilita o histórico da Área de Transferência e a Área de Transferência na Nuvem.
echo Desabilitando o Histórico da Área de Transferência e a Área de Transferência na Nuvem.
:: (Nota: Os comandos a seguir são os mesmos que os de "Handwriting telemetry". Verifique se esta é a intenção correta para "Clipboard history".)
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

:: Desabilita anúncios direcionados e a coleta de dados de conteúdo em nuvem do Windows.
echo Desabilitando Anúncios Direcionados e Coleta de Dados.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightFeatures" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f
reg add "HKCU\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t "REG_DWORD" /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /d "0" /t REG_DWORD /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /d "0" /t REG_DWORD /f

:: Opta por não aceitar o consentimento de privacidade do Windows.
echo Optando por não aceitar o consentimento de privacidade.
reg add "HKCU\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f

:: Desabilita a telemetria da Adobe adicionando entradas ao arquivo hosts.
echo Desabilitando a Telemetria da Adobe.
set "hostspath=%windir%\System32\drivers\etc\hosts"
set "downloadedlist=%temp%\list.txt"
echo Baixando a lista de entradas de host.
curl -s -o "%downloadedlist%" "https://a.dove.isdumb.one/list.txt"
if not exist "%downloadedlist%" (
    echo Falha ao baixar a lista da URL especificada.
    exit /b 1
)
echo Entradas de bloqueio da Adobe adicionadas com sucesso ao arquivo hosts.
type "%downloadedlist%" >> "%hostspath%"
del "%downloadedlist%"

:: Desabilita a telemetria da NVIDIA, incluindo tarefas agendadas.
echo Desabilitando a Telemetria da NVIDIA.
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE > NUL 2>&1
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE > NUL 2>&1
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE > NUL 2>&1

:: Desabilita a telemetria do Visual Studio.
echo Desabilitando a Telemetria do Visual Studio.
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d 1 /f
reg delete "HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub" /v "LogLevel" /f 2>nul
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode" /v "DisableRemoteAnalysis" /t "REG_DWORD" /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode" /v "DisableRemoteAnalysis" /t "REG_DWORD" /d "1" /f
reg add "HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode" /v "DisableRemoteAnalysis" /t "REG_DWORD" /d "1" /f

:: Desabilita a telemetria do Media Player.
echo Desabilitando a Telemetria do Media Player.
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f

:: Desabilita a telemetria do PowerShell.
echo Desabilitando a telemetria do PowerShell.
setx POWERSHELL_TELEMETRY_OPTOUT 1

:: Desabilita a telemetria do CCleaner e recursos de monitoramento/atualização automática.
echo Desabilitando a telemetria do CCleaner.
reg add "HKCU\Software\Piriform\CCleaner" /v "Monitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "HelpImproveCCleaner" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "SystemMonitoring" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateAuto" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "UpdateCheck" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Piriform\CCleaner" /v "CheckTrialOffer" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)HealthCheck" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickClean" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)QuickCleanIpm" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)GetIpmForTrial" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdater" /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Piriform\CCleaner" /v "(Cfg)SoftwareUpdaterIpm" /t REG_DWORD /d 0 /f

:: Desabilita os serviços de atualização do Google.
echo Desabilitando atualizações do Google.
sc config gupdate start=disabled
sc config gupdatem start=disabled

:: Desabilita as tarefas de atualização e serviços do Adobe.
echo Desabilitando atualizações do Adobe.
schtasks /change /TN "\Adobe Acrobat Update Task" /DISABLE > NUL 2>&1
sc config AdobeARMservice start=disabled
sc config adobeupdateservice start=disabled

:: Desabilita recursos de consumidor do Windows, como sugestões de aplicativos e conteúdo promocional.
echo Desabilitando Recursos de Consumidor.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t "REG_DWORD" /d "1" /f

:: Desabilita o recurso "Recall" do Windows.
echo Desabilitando o Recall.
DISM /Online /Disable-Feature /FeatureName:Recall

:: Desabilita o Internet Explorer.
echo Desabilitando o Internet Explorer.
dism /online /Remove-Capability /CapabilityName:Browser.InternetExplorer~~~~0.0.11.0.

:: Desabilita o Hyper-V.
echo Desabilitando o Hyper-V.
powershell -Command "try { Disable-WindowsOptionalFeature -FeatureName "Microsoft-Hyper-V-All" -Online -NoRestart -ErrorAction Stop; Write-Output "Successfully disabled the feature Microsoft-Hyper-V-All." } catch { Write-Output "Feature not found." }"

:: Desabilita e interrompe o serviço de Fax e Digitalização do Windows.
echo Desabilitando Fax e Digitalização.
dism /Online /Disable-Feature /FeatureName:FaxServicesClientPackage
sc stop Fax
sc config Fax start=demand

:: Desabilita o Windows Media Player.
echo Desabilitando o Windows Media Player.
powershell -Command "try { Disable-WindowsOptionalFeature -FeatureName "WindowsMediaPlayer" -Online -NoRestart -ErrorAction Stop; Write-Output "Successfully disabled the feature WindowsMediaPlayer." } catch { Write-Output "Feature not found." }"

:: Desabilita a coleta de dados de texto e escrita à mão para personalização de entrada.
echo Desabilitando a coleta de dados de texto e escrita à mão.
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f

:: Desabilita os sensores do dispositivo.
echo Desabilitando sensores do dispositivo.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d "1" /f

:: Desabilita o Wi-Fi Sense, impedindo compartilhamento de rede e conexão automática.
echo Desabilitando Wi-Fi Sense.
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config" /v "AutoConnectAllowedOEM" /t REG_DWORD /d 0 /f

:: Desabilita o rastreamento de inicialização de aplicativos (esconde aplicativos mais usados).
echo Desabilitando o rastreamento de inicialização de aplicativos.
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /d 0 /t REG_DWORD /f

:: Desabilita o acesso de sites à lista de idiomas do usuário.
echo Desabilitando o acesso de sites à lista de idiomas.
reg add "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f

:: Desabilita downloads automáticos de mapas.
echo Desabilitando downloads automáticos de mapas.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AllowUntriggeredNetworkTrafficOnSettingsPage" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f

:: Desabilita a gravação de tela de jogos (Game DVR).
echo Desabilitando a gravação de tela de jogos.
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f

:: Desabilita o acesso à internet para o DRM do Windows.
echo Desabilitando o acesso à internet para o DRM do Windows.
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f

:: Desabilita o feedback de digitação (envio de dados de digitação).
echo Desabilitando o feedback de digitação.
reg add "HKLM\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d 0 /f

:: Desabilita o recurso "Activity Feed".
echo Desabilitando o recurso Activity Feed.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /d "0" /t REG_DWORD /f

:: Desabilita a participação no Programa de Aperfeiçoamento da Experiência do Cliente do Visual Studio (VSCEIP).
echo Desabilitando a participação no Programa de Aperfeiçoamento da Experiência do Cliente do Visual Studio (VSCEIP).
if %PROCESSOR_ARCHITECTURE%==x86 ( REM É 32 bits?
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
) else (
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\14.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\15.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\16.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
    reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\VSCommon\17.0\SQM" /v "OptIn" /t REG_DWORD /d 0 /f
)
reg add "HKLM\Software\Policies\Microsoft\VisualStudio\SQM" /v "OptIn" /t REG_DWORD /d 0 /f

:: Desabilita a telemetria geral do Visual Studio.
echo Desabilitando a telemetria do Visual Studio.
reg add "HKCU\Software\Microsoft\VisualStudio\Telemetry" /v "TurnOffSwitch" /t REG_DWORD /d 1 /f

:: Desabilita o envio de feedback do Visual Studio.
echo Desabilitando o feedback do Visual Studio.
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableFeedbackDialog" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableEmailInput" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\Feedback" /v "DisableScreenshotCapture" /t REG_DWORD /d 1 /f

:: Interrompe e desabilita o serviço coletor padrão do Visual Studio.
echo Parando e desabilitando o serviço Coletor Padrão do Visual Studio.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'VSStandardCollectorService150'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"

:: Desabilita a coleta de log do Diagnostics Hub do Visual Studio.
echo Desabilitando a coleta de log do Diagnostics Hub.
reg delete "HKLM\Software\Microsoft\VisualStudio\DiagnosticsHub" /v "LogLevel" /f 2>nul

:: Desabilita a participação na coleta de dados do IntelliCode do Visual Studio.
echo Desabilitando a participação na coleta de dados do IntelliCode.
reg add "HKLM\SOFTWARE\Policies\Microsoft\VisualStudio\IntelliCode" /v "DisableRemoteAnalysis" /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\VSCommon\16.0\IntelliCode" /v "DisableRemoteAnalysis" /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\VSCommon\17.0\IntelliCode" /v "DisableRemoteAnalysis" /d 1 /f

:: Remove as tarefas de telemetria da NVIDIA.
echo Removendo as tarefas de telemetria da NVIDIA.
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)

:: Limpa os arquivos de telemetria residuais da NVIDIA.
echo Limpando arquivos de telemetria residuais da NVIDIA.
del /s %SystemRoot%\System32\DriverStore\FileRepository\NvTelemetry*.dll
rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2>nul
rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2>nul

:: Desabilita a participação na telemetria da NVIDIA via registro.
echo Desabilitando a participação na telemetria da NVIDIA.
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f

:: Desabilita o serviço "Nvidia Telemetry Container".
echo Desabilitando o serviço Nvidia Telemetry Container.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'NvTelemetryContainer'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"

:: Desabilita as tarefas de telemetria da NVIDIA.
echo Desabilitando as tarefas de telemetria da NVIDIA.
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE > NUL 2>&1
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE > NUL 2>&1
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE > NUL 2>&1

:: Desabilita a telemetria do Visual Studio Code.
echo Desabilitando a telemetria do Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='telemetry.enableTelemetry'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita o relatório de falhas do Visual Studio Code.
echo Desabilitando o relatório de falhas do Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='telemetry.enableCrashReporter'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita experimentos online da Microsoft no Visual Studio Code.
echo Desabilitando experimentos online da Microsoft no Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='workbench.enableExperiments'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita atualizações automáticas do Visual Studio Code em favor de atualizações manuais.
echo Desabilitando atualizações automáticas do Visual Studio Code em favor de atualizações manuais.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='update.mode'; $settingValue='manual'; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita a busca automática de notas de lançamento dos servidores da Microsoft após uma atualização do Visual Studio Code.
echo Desabilitando a busca de notas de lançamento dos servidores da Microsoft após uma atualização.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='update.showReleaseNotes'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita a verificação automática de extensões de um serviço online da Microsoft no Visual Studio Code.
echo Desabilitando a verificação automática de extensões do serviço online da Microsoft.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='extensions.autoCheckUpdates'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Garante que as recomendações de extensão do Visual Studio Code sejam buscadas apenas sob demanda.
echo Buscando recomendações de extensão do Visual Studio Code apenas sob demanda.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='extensions.showRecommendationsOnlyOnDemand'; $settingValue=$true; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita a busca automática de repositórios remotos no Visual Studio Code.
echo Desabilitando a busca automática de repositórios remotos no Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='git.autofetch'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita a busca de informações de pacotes de NPM e Bower no Visual Studio Code.
echo Desabilitando a busca de informações de pacotes de NPM e Bower no Visual Studio Code.
PowerShell -ExecutionPolicy Unrestricted -Command "$settingKey='npm.fetchOnlinePackageInfo'; $settingValue=$false; $jsonFilePath = "^""$($env:APPDATA)\Code\User\settings.json"^""; if (!(Test-Path $jsonFilePath -PathType Leaf)) {; Write-Host "^""Ignorando, sem atualizações. O arquivo de configurações não estava em `"^""$jsonFilePath`"^""."^""; exit 0; }; try {; $fileContent = Get-Content $jsonFilePath -ErrorAction Stop; } catch {; throw "^""Erro, falha ao ler o arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; if ([string]::IsNullOrWhiteSpace($fileContent)) {; Write-Host "^""O arquivo de configurações está vazio. Tratando-o como um objeto JSON vazio padrão."^""; $fileContent = "^""{}"^""; }; try {; $json = $fileContent | ConvertFrom-Json; } catch {; throw "^""Erro, formato JSON inválido no arquivo de configurações: `"^""$jsonFilePath`"^"". Erro: $_"^""; }; $existingValue = $json.$settingKey; if ($existingValue -eq $settingValue) {; Write-Host "^""Ignorando, `"^""$settingKey`"^"" já está configurado como `"^""$settingValue`"^""."^""; exit 0; }; $json | Add-Member -Type NoteProperty -Name $settingKey -Value $settingValue -Force; $json | ConvertTo-Json | Set-Content $jsonFilePath; Write-Host "^""Configuração aplicada com sucesso ao arquivo: `"^""$jsonFilePath`"^""."^"""

:: Desabilita o log de atividades no Microsoft Office, incluindo e-mail, calendário e documentos.
echo Desabilitando o log do Microsoft Office.
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Mail" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Outlook\Options\Calendar" /v "EnableCalendarLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Word\Options" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\15.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Policies\Microsoft\Office\16.0\OSM" /v "EnableUpload" /t REG_DWORD /d 0 /f

:: Desabilita a telemetria do cliente Microsoft Office.
echo Desabilitando a telemetria do cliente Microsoft Office.
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "DisableTelemetry" /t REG_DWORD /d 1 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\ClientTelemetry" /v "VerboseLogging" /t REG_DWORD /d 0 /f

:: Desabilita a participação no Programa de Aperfeiçoamento da Experiência do Cliente do Microsoft Office.
echo Desabilitando o Programa de Aperfeiçoamento da Experiência do Cliente do Microsoft Office.
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common" /v "QMEnable" /t REG_DWORD /d 0 /f

:: Desabilita o envio de feedback do Microsoft Office.
echo Desabilitando o feedback do Microsoft Office.
reg add "HKCU\SOFTWARE\Microsoft\Office\15.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Office\16.0\Common\Feedback" /v "Enabled" /t REG_DWORD /d 0 /f

:: Desabilita as tarefas agendadas do agente de telemetria do Microsoft Office.
echo Desabilitando o agente de telemetria do Microsoft Office.
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack2016" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn2016" /DISABLE > NUL 2>&1

:: Desabilita as tarefas agendadas do "Heartbeat de Assinatura" do Microsoft Office.
echo Desabilitando o Heartbeat de Assinatura do Microsoft Office.
schtasks /change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /DISABLE > NUL 2>&1
schtasks /change /TN "Microsoft\Office\Office 16 Subscription Heartbeat" /DISABLE > NUL 2>&1

:: Desabilita o envio de dados de diagnóstico do Edge. Pode mostrar "Seu navegador é gerenciado".
echo Desabilitando o envio de dados de diagnóstico do Edge.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "SendSiteInfoToImproveServices" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v "DiagnosticData" /t REG_DWORD /d 0 /f

:: Desabilita a instalação automática do Edge (Chromium).
echo Desabilitando a instalação automática do Edge (Chromium).
reg add "HKLM\SOFTWARE\Microsoft\EdgeUpdate" /v "DoNotUpdateToEdgeWithChromium" /t REG_DWORD /d 1 /f

:: Desabilita a coleta de dados de Live Tile.
echo Desabilitando a coleta de dados de Live Tile.
reg add "HKCU\Software\Policies\Microsoft\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d 1 /f

:: Desabilita o rastreamento de aplicativos mais usados (MFU).
echo Desabilitando o rastreamento MFU.
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableMFUTracking" /t REG_DWORD /d 1 /f

:: Desabilita a exibição de aplicativos recentes.
echo Desabilitando aplicativos recentes.
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "DisableRecentApps" /t REG_DWORD /d 1 /f

:: Desabilita o recurso de retrocesso (backtracking).
echo Desabilitando o retrocesso.
reg add "HKCU\Software\Policies\Microsoft\Windows\EdgeUI" /v "TurnOffBackstack" /t REG_DWORD /d 1 /f

:: Desabilita as sugestões de pesquisa no Edge.
echo Desabilitando as sugestões de pesquisa no Edge.
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\SearchScopes" /v "ShowSearchSuggestionsGlobal" /t REG_DWORD /d 0 /f

:: Desabilita a geolocalização no Internet Explorer.
echo Desabilitando a geolocalização do Internet Explorer.
reg add "HKCU\Software\Policies\Microsoft\Internet Explorer\Geolocation" /v "PolicyDisableGeolocation" /t REG_DWORD /d 1 /f

:: Desabilita o log de navegação InPrivate no Internet Explorer.
echo Desabilitando o log InPrivate do Internet Explorer.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\Safety\PrivacIE" /v "DisableLogging" /t REG_DWORD /d 1 /f

:: Desabilita o Programa de Aperfeiçoamento da Experiência do Cliente (CEIP) no Internet Explorer.
echo Desabilitando o CEIP do Internet Explorer.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Internet Explorer\SQM" /v "DisableCustomerImprovementProgram" /t REG_DWORD /d 0 /f

:: Desabilita chamadas de política WCM legadas.
echo Desabilitando chamadas de política WCM legadas.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "CallLegacyWCMPolicies" /t REG_DWORD /d 0 /f

:: Desabilita o fallback para SSLv3.
echo Desabilitando o fallback para SSLv3.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "EnableSSL3Fallback" /t REG_DWORD /d 0 /f

:: Desabilita a opção de ignorar erros de certificado.
echo Desabilitando a ignorância de erros de certificado.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "PreventIgnoreCertErrors" /t REG_DWORD /d 1 /f

:: Desabilita o compartilhamento de dados de software escaneados com o Google no Chrome. Pode mostrar "Seu navegador é gerenciado".
echo Desabilitando o compartilhamento de dados de software escaneados com o Google (Chrome).
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupReportingEnabled" /t REG_DWORD /d 0 /f

:: Desabilita as varreduras de limpeza do sistema do Chrome. Pode mostrar "Seu navegador é gerenciado".
echo Desabilitando as varreduras de limpeza do sistema do Chrome.
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "ChromeCleanupEnabled" /t REG_DWORD /d 0 /f

:: Desabilita a ferramenta de relatório de software do Chrome.
echo Desabilitando a ferramenta de relatório de software do Chrome.
icacls "%LOCALAPPDATA%\Google\Chrome\User Data\SwReporter" /inheritance:r /deny "*S-1-1-0:(OI)(CI)(F)" "*S-1-5-7:(OI)(CI)(F)"
cacls "%LOCALAPDATA%\Google\Chrome\User Data\SwReporter" /e /c /d %username%
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "1" /t REG_SZ /d "software_reporter_tool.exe" /f

:: Desabilita o relatório de métricas do Chrome. Pode mostrar "Seu navegador é gerenciado".
echo Desabilitando o relatório de métricas do Chrome.
reg add "HKLM\SOFTWARE\Policies\Google\Chrome" /v "MetricsReportingEnabled" /t REG_DWORD /d 0 /f

:: Desabilita o relatório do agente de navegador padrão do Firefox.
echo Desabilitando o relatório do agente de navegador padrão do Firefox.
reg add HKLM\SOFTWARE\Policies\Mozilla\Firefox /v DisableDefaultBrowserAgent /t REG_DWORD /d 1 /f

:: Desabilita os serviços que relatam o agente de navegador padrão do Firefox.
echo Desabilitando os serviços que relatam o agente de navegador padrão do Firefox.
schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent 308046B0AF4A39CB" > NUL 2>&1
schtasks.exe /change /disable /tn "\Mozilla\Firefox Default Browser Agent D2CEEC440E2074BD" > NUL 2>&1

:: Desabilita o relatório de métricas do Firefox.
echo Desabilitando o relatório de métricas do Firefox.
reg add HKLM\SOFTWARE\Policies\Mozilla\Firefox /v DisableTelemetry /t REG_DWORD /d 1 /f

:: Desabilita o envio de estatísticas do Windows Media Player.
echo Desabilitando o envio de estatísticas do Windows Media Player.
reg add "HKCU\SOFTWARE\Microsoft\MediaPlayer\Preferences" /v "UsageTracking" /t REG_DWORD /d 0 /f

:: Desabilita a recuperação de metadados para CDs, DVDs, arquivos de música e predefinições de rádio no Windows Media Player.
echo Desabilitando a recuperação de metadados.
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventCDDVDMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Policies\Microsoft\WindowsMediaPlayer" /v "PreventRadioPresetsRetrieval" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /f

:: Desabilita o "Serviço de Compartilhamento de Rede do Windows Media Player" (WMPNetworkSvc).
echo Desabilitando o "Serviço de Compartilhamento de Rede do Windows Media Player" (`WMPNetworkSvc`).
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'WMPNetworkSvc'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"

:: Desabilita a telemetria do .NET Core CLI.
echo Desabilitando a telemetria do NET Core CLI.
setx DOTNET_CLI_TELEMETRY_OPTOUT 1

:: Desabilita a telemetria do PowerShell.
echo Desabilitando a telemetria do PowerShell.
setx POWERSHELL_TELEMETRY_OPTOUT 1

:: Desabilita os serviços de atualização do Google.
echo Desabilitando os serviços de atualização do Google.
schtasks /change /disable /tn "GoogleUpdateTaskMachineCore" > NUL 2>&1
schtasks /change /disable /tn "GoogleUpdateTaskMachineUA" > NUL 2>&1
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'gupdate'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'gupdatem'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"

:: Desabilita os serviços de atualização do Adobe Acrobat e Flash Player.
echo Desabilitando os serviços de atualização do Adobe Acrobat.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'AdobeARMservice'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'adobeupdateservice'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'adobeflashplayerupdatesvc'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"
schtasks /change /tn "Adobe Acrobat Update Task" /disable > NUL 2>&1
schtasks /change /tn "Adobe Flash Player Updater" /disable > NUL 2>&1

:: Desabilita o "Razer Game Scanner Service".
echo Desabilitando o "Razer Game Scanner Service".
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'Razer Game Scanner Service'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"

:: Desabilita o "Logitech Gaming Registry Service".
echo Desabilitando o "Logitech Gaming Registry Service".
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'LogiRegistryService'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"

:: Desabilita os serviços de atualização automática do Dropbox.
echo Desabilitando os serviços de atualização automática do Dropbox.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dbupdate'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'dbupdatem'; Write-Host "^""Desabilitando serviço: `"^""$serviceName`"^""."^""; <# -- 1. Ignorar se o serviço não existe #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Serviço `"^""$serviceName`"^"" não encontrado, não é necessário desabilitá-lo."^""; Exit 0; }; <# -- 2. Parar se estiver em execução #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" está em execução, parando-o."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Parado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Warning "^""Não foi possível parar `"^""$serviceName`"^"", ele será parado após a reinicialização: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" não está em execução, não é necessário parar."^""; }; <# -- 3. Ignorar se já estiver desabilitado #>; $startupType = $service.StartType <# Não funciona antes do .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName já está desabilitado, nenhuma ação adicional é necessária"^""; }; <# -- 4. Desabilitar serviço #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Desabilitado `"^""$serviceName`"^"" com sucesso."^""; } catch {; Write-Error "^""Não foi possível desabilitar `"^""$serviceName`"^"": $_"^""; }"
schtasks /Change /DISABLE /TN "DropboxUpdateTaskMachineCore" > NUL 2>&1
schtasks /Change /DISABLE /TN "DropboxUpdateTaskMachineUA" > NUL 2>&1

:: Desabilita o recurso "Block at First Sight" do Windows Defender.
echo Desabilitando o "Block at First Sight".
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableBlockAtFirstSeen'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableBlockAtFirstSeen $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f

:: Maximiza o tempo limite para a verificação estendida na nuvem do Windows Defender.
echo Maximizando o tempo limite para verificação estendida na nuvem.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpBafsExtendedTimeout" /t REG_DWORD /d 50 /f

:: Minimiza o nível de proteção na nuvem do Windows Defender.
echo Minimizando o nível de proteção na nuvem.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpCloudBlockLevel" /t REG_DWORD /d 0 /f

:: Desabilita as notificações para desligar a inteligência de segurança do Windows Defender.
echo Desabilitando notificações para desligar a inteligência de segurança.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "SignatureDisableNotification" /t REG_DWORD /d 0 /f

:: Desabilita o relatório do Microsoft Defender SpyNet.
echo Desabilitando o relatório do Microsoft Defender SpyNet.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'MAPSReporting'; $value = '0'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -MAPSReporting $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d "0" /f

:: Desabilita o envio de amostras de arquivos para análise adicional.
echo Desabilitando o envio de amostras de arquivos para análise.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'SubmitSamplesConsent'; $value = '2'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -SubmitSamplesConsent $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f

:: Desabilita o envio de dados de diagnóstico da ferramenta "Malicious Software Reporting".
echo Desabilitando dados de diagnóstico da ferramenta "Malicious Software Reporting".
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f

:: Desabilita o upload de arquivos para análise de ameaças em tempo real.
echo Desabilitando o upload de arquivos para análise de ameaças em tempo real.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Signature Updates" /v "RealtimeSignatureDelivery" /t REG_DWORD /d 0 /f

:: Desabilita a prevenção de acesso a sites perigosos por usuários e aplicativos (Proteção de Rede).
echo Desabilitando a prevenção de acesso a sites perigosos.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Network Protection" /v "EnableNetworkProtection" /t REG_DWORD /d "1" /f

:: Desabilita o acesso controlado a pastas.
echo Desabilitando o acesso controlado a pastas.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d "0" /f

:: Desabilita o reconhecimento de protocolo no Windows Defender NIS.
echo Desabilitando o reconhecimento de protocolo.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS" /v "DisableProtocolRecognition" /t REG_DWORD /d "1" /f

:: Desabilita a desativação de definições (definição de expiração).
echo Desabilitando a desativação de definições.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "DisableSignatureRetirement" /t REG_DWORD /d "1" /f

:: Minimiza a taxa de eventos de detecção no Windows Defender.
echo Minimizando a taxa de eventos de detecção.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\NIS\Consumers\IPS" /v "ThrottleDetectionEventsRate" /t REG_DWORD /d "10000000" /f

:: Desabilita o monitoramento de comportamento em tempo real do Windows Defender.
echo Desabilitando o monitoramento de comportamento.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableBehaviorMonitoring'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableBehaviorMonitoring $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f

:: Desabilita o envio de notificações de gravação bruta para o monitoramento de comportamento.
echo Desabilitando o envio de notificações de gravação bruta para monitoramento de comportamento.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRawWriteNotification" /t REG_DWORD /d "1" /f

:: Desabilita a verificação de todos os arquivos e anexos baixados pelo Windows Defender.
echo Desabilitando a verificação de todos os arquivos e anexos baixados.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableIOAVProtection'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableIOAVProtection $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f

:: Desabilita a verificação de arquivos maiores que 1 KB (mínimo possível).
echo Desabilitando a verificação de arquivos maiores que 1 KB.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "IOAVMaxSize" /t REG_DWORD /d "1" /f

:: Desabilita o monitoramento de atividades de arquivos e programas.
echo Desabilitando o monitoramento de atividades de arquivos e programas.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f

:: Desabilita a verificação bidirecional para atividades de entrada e saída de arquivos e programas.
echo Desabilitando a verificação bidirecional para atividades de arquivos e programas.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'RealTimeScanDirection'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -RealTimeScanDirection $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "RealTimeScanDirection" /t REG_DWORD /d "1" /f

:: Desabilita o monitoramento em tempo real do Windows Defender.
echo Desabilitando o monitoramento em tempo real.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableRealtimeMonitoring'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableRealtimeMonitoring $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } el"

:: Desabilita as ações de remediação padrão para ameaças desconhecidas e define a ação para "Remover" (valor 9) para todos os níveis de gravidade de ameaças.
echo Desabilitando ações de remediação.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'UnknownThreatDefaultAction'; $value = '9'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -UnknownThreatDefaultAction $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats" /v "Threats_ThreatSeverityDefaultAction" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "5" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "4" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "3" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "2" /t "REG_SZ" /d "9" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Threats\ThreatSeverityDefaultAction" /v "1" /t "REG_SZ" /d "9" /f

:: Habilita a limpeza automática de itens da pasta de quarentena após 1 dia.
echo Habilitando a limpeza automática de itens da quarentena.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'QuarantinePurgeItemsAfterDelay'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -QuarantinePurgeItemsAfterDelay $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Quarantine" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f

:: Desabilita a verificação de assinatura antes de executar uma varredura.
echo Desabilitando a verificação de assinatura antes da varredura.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'CheckForSignaturesBeforeRunningScan'; $value = $False; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -CheckForSignaturesBeforeRunningScan $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d "0" /f

:: Desabilita a criação de pontos de restauração diários pelo Windows Defender.
echo Desabilitando a criação de pontos de restauração diários.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableRestorePoint'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableRestorePoint $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableRestorePoint" /t REG_DWORD /d "1" /f

:: Minimiza o tempo de retenção para arquivos no histórico de varredura (1 dia).
echo Minimizando o tempo de retenção do histórico de varredura.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanPurgeItemsAfterDelay'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanPurgeItemsAfterDelay $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "PurgeItemsAfterDelay" /t REG_DWORD /d "1" /f

:: Maximiza os dias até a varredura obrigatória de "catch-up" (20 dias).
echo Maximizando os dias até a varredura obrigatória de catch-up.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "MissedScheduledScanCountBeforeCatchup" /t REG_DWORD /d "20" /f

:: Desabilita as varreduras completas de "catch-up".
echo Desabilitando varreduras completas de catch-up.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableCatchupFullScan'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableCatchupFullScan $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupFullScan" /t REG_DWORD /d "1" /f

:: Desabilita as varreduras rápidas de "catch-up".
echo Desabilitando varreduras rápidas de catch-up.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableCatchupQuickScan'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableCatchupQuickScan $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCatchupQuickScan" /t REG_DWORD /d "1" /f

:: Minimiza o uso da CPU durante as varreduras para 1%.
echo Minimizando o uso da CPU durante as varreduras.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanAvgCPULoadFactor'; $value = '1'; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanAvgCPULoadFactor $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "AvgCPULoadFactor" /t REG_DWORD /d "1" /f

:: Minimiza o uso da CPU durante varreduras em modo ocioso (desabilita a limitação).
echo Minimizando o uso da CPU durante varreduras em modo ocioso.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableCpuThrottleOnIdleScans'; $value = $False; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableCpuThrottleOnIdleScans $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableCpuThrottleOnIdleScans" /t REG_DWORD /d "0" /f

:: Desabilita a heurística de varredura do Windows Defender.
echo Desabilitando a heurística de varredura.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d "1" /f

:: Desabilita a varredura quando o sistema não está ocioso.
echo Desabilitando a varredura quando o sistema não está ocioso.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'ScanOnlyIfIdleEnabled'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -ScanOnlyIfIdleEnabled $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ScanOnlyIfIdle" /t REG_DWORD /d "1" /f

:: Desabilita o scanner anti-malware agendado (MRT).
echo Desabilitando o scanner anti-malware agendado (MRT).
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f

:: Desabilita a varredura de arquivos compactados.
echo Desabilitando a varredura de arquivos compactados.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableArchiveScanning'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableArchiveScanning $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"

:: Minimiza a profundidade de varredura de arquivos compactados para 0.
echo Minimizando a profundidade de varredura de arquivos compactados.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxDepth" /t REG_DWORD /d "0" /f

:: Minimiza o tamanho do arquivo para varredura de arquivos compactados para 1 KB.
echo Minimizando o tamanho do arquivo para varredura de arquivos compactados.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "ArchiveMaxSize" /t REG_DWORD /d "1" /f

:: Desabilita a varredura de e-mail pelo Windows Defender.
echo Desabilitando a varredura de e-mail.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableEmailScanning'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableEmailScanning $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d "1" /f

:: Desabilita a varredura de scripts pelo Windows Defender.
echo Desabilitando a varredura de scripts.
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableScriptScanning'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableScriptScanning $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"

:: Desabilita a varredura de pontos de reparse.
echo Desabilitando a varredura de pontos de reparse.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableReparsePointScanning" /t REG_DWORD /d "1" /f

:: Desabilita a varredura de unidades de rede mapeadas durante a varredura completa.
echo Desabilitando a varredura de unidades de rede mapeadas durante a varredura completa.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableScanningMappedNetworkDrivesForFullScan'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableScanningMappedNetworkDrivesForFullScan $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"

:: Desabilita a varredura de arquivos de rede.
echo Desabilitando a varredura de arquivos de rede.
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningNetworkFiles" /t REG_DWORD /d "1" /f
PowerShell -ExecutionPolicy Unrestricted -Command "$propertyName = 'DisableScanningNetworkFiles'; $value = $True; if((Get-MpPreference -ErrorAction Ignore).$propertyName -eq $value) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" já está `"^""$value`"^"" conforme desejado."^""; exit 0; }; $command = Get-Command 'Set-MpPreference' -ErrorAction Ignore; if (!$command) {; Write-Warning 'Ignorando. Comando não encontrado: "^""Set-MpPreference"^"".'; exit 0; }; if(!$command.Parameters.Keys.Contains($propertyName)) {; Write-Host "^""Ignorando. `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; }; try {; Invoke-Expression "^""$($command.Name) -Force -$propertyName `$value -ErrorAction Stop"^""; Set-MpPreference -Force -DisableScanningNetworkFiles $value -ErrorAction Stop; Write-Host "^""Definido com sucesso `"^""$propertyName`"^"" para `"^""$value`"^""."^""; exit 0; } catch {; if ( $_.FullyQualifiedErrorId -like '*0x800106ba*') {; Write-Warning "^""Não é possível $($command.Name): O serviço do Defender (WinDefend) não está em execução. Tente habilitá-lo (reverter) e execute novamente?"^""; exit 0; } elseif (($_ | Out-String) -like '*Cannot convert*') {; Write-Host "^""Ignorando. Argumento `"^""$value`"^"" para a propriedade `"^""$propertyName`"^"" não é suportado para `"^""$($command.Name)`"^""."^""; exit 0; } else {; Write-Error "^""Falha ao definir usando $($command.Name): $_"^""; exit 1; }; }"


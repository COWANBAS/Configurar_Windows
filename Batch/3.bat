:: Removendo integração do one drive
echo Remove integração do OneDrive.
REG Delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
REG Delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
REG Delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:32
REG Delete "HKCU\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:64
REG Delete "HKLM\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:32
REG Delete "HKLM\SOFTWARE\Classes\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f /reg:64

:: Removendo pastas especiais
echo Remove pastas especiais do Explorer.
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}" /f
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{339719B5-8C47-4894-94C2-D8F77ADD44A6}" /f
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{767E6811-49CB-4273-87C2-20F355E1085B}" /f
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{C3F2459E-80D6-45DC-BFEF-1F769F2BE730}" /f
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{24D89E24-2F19-4534-9DDE-6A6671FBB8FE}" /f
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{2B20DF75-1EDA-4039-8097-38798227D5B7}" /f
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{31C0DD25-9439-4F12-BF41-7FF4EDA38722}" /f

:: Removendo icone do one drive
echo Remove ícones do OneDrive do Meu Computador.
REG Delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f
REG Delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f
REG Delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}" /f

:: Removendo sincronização do OndeDrive
echo Remove política que desabilita sincronização do OneDrive.
REG Delete "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /f

:: Removendo Security Health
echo Remove inicialização do SecurityHealth.
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f

:: Removendo menu EPP
echo Remove menu de contexto do EPP.
reg delete "HKCR\*\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Directory\shellex\ContextMenuHandlers\EPP" /f
reg delete "HKCR\Drive\shellex\ContextMenuHandlers\EPP" /f


:: Removendo tela de proteção do SmartScreen
echo Remove política de proteção do Shell SmartScreen.
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "ShellSmartScreenLevel" /F

:: Removendo indentificador de Ads do windows
echo Remove identificador de publicidade do sistema.
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Id" /f 1>NUL 2>NUL

:: Remover indentificador de Ads do usuário
echo Remove identificador de publicidade do usuário.
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Id" /f 1>NUL 2>NUL
REG Delete "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Id" /f

:: Remover politicas do Windows Defender
echo Remove chave de políticas do Windows Defender.
reg delete "HKLM\Software\Policies\Microsoft\Windows Defender" /f

:: Desabilita serviços de atualização do Windows
echo Desabilitando serviço WaasMedicSvc...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\WaasMedicSvc" /v Start /f /t REG_DWORD /d 4

echo Desabilitando serviço Windows Update (wuauserv)...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /f /t REG_DWORD /d 4

echo Desabilitando serviço Update Orchestrator Service (UsoSvc)...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\UsoSvc" /v Start /f /t REG_DWORD /d 4

:: Remove ícone do OneDrive do Meu Computador
echo Removendo integração do OneDrive do Meu Computador...
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" /f

:: Oculta a pasta Documentos do Explorer
echo Ocultando pasta Documentos do Explorer...
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{a0c69a99-21c8-4671-8703-7934162fcf1d}\PropertyBag" /v "ThisPCPolicy" /t REG_SZ /d "Hide" /f

:: Desabilita imagem de fundo na tela de logon
echo Desabilitando imagem de fundo na tela de logon...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableLogonBackgroundImage" /t REG_DWORD /d 1 /f

:: Configura preferências de acessibilidade do teclado
echo Habilitando preferência de teclado de acessibilidade...
REG ADD "HKCU\Control Panel\Accessibility\Keyboard Preference" /v "On" /t REG_SZ /d 1 /f

echo Configurando opções da barra de busca do Windows...
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f

echo Desabilitando rastreamento de documentos recentes no menu Iniciar...
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

echo Configurando Sticky Keys e outras opções de acessibilidade...
REG ADD "HKCU\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d "506" /f
REG ADD "HKCU\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d "122" /f

:: Wi-Fi Sense e relatórios de hotspot
echo Desabilitando conexão automática ao Wi-Fi Sense e relatórios de hotspot...
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v "value" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v "value" /t REG_DWORD /d 0 /f

:: Windows Defender - desativa proteção em tempo real e outras ações
echo Desabilitando partes do Windows Defender...
REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Policy Manager" /f
REG ADD "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f

:: Notificações e centro de ações
echo Desabilitando Centro de Notificações do Windows...
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableNotificationCenter" /t REG_DWORD /d 1 /f

:: Desabilitando SMB1/SMB2
echo Desabilitando protocolos SMB1 e SMB2...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB2 /t REG_DWORD /d 0 /f

:: Desabilitando histórico de documentos recentes
echo Desabilitando histórico de documentos recentes...
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f

:: Configurações de telemetria, privacidade e busca
echo Ajustando configurações de telemetria, privacidade e busca...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
REG ADD "HKCU\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d 1 /f

:: Configurações do Office (telemetria, feedback, upload, etc)
echo Ajustando configurações de privacidade no Office...
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\15.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "qmenable" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "sendcustomerdata" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common" /v "updatereliabilitydata" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "enabled" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\feedback" /v "includescreenshot" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\internet" /v "useonlinecontent" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\common\ptwatson" /v "ptwoptin" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablefileobfuscation" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enablelogging" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm" /v "enableupload" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "accesssolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "olksolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "onenotesolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "pptsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "projectsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "publishersolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "visiosolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "wdsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedapplications" /v "xlsolution" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "agave" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "appaddins" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "comaddins" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "documentfiles" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\osm\preventedsolutiontypes" /v "templatefiles" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\excel\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\outlook\security" /v "level" /t REG_DWORD /d 2 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\powerpoint\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\office\16.0\word\security" /v "blockcontentexecutionfrominternet" /t REG_DWORD /d 0 /f

:: Skype - desativa rastreamento e define local de log
echo Desabilitando rastreamento do Skype e definindo local do log...
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "TraceLevelThreshold" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "EnableTracing" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "EnableTracing" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\Tracing\WPPMedia" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Tracing\WPPMediaPerApp\Skype\ETW" /v "WPPFilePath" /t REG_SZ /d "%%SYSTEMDRIVE%%\TEMP\WPPMedia" /f

:: Desabilita inicialização rápida
echo Desabilitando inicialização rápida...
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f

:: Desativa recursos online do DRM
echo Desabilitando recursos online do Windows Media DRM...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\WMDRM" /v "DisableOnline" /t REG_DWORD /d 1 /

:: Configurações do Windows Error Reporting
echo Ajustando configurações do Windows Error Reporting...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v "AutoApproveOSDumps" /t REG_DWORD /d 0 /f

:: Outras políticas de sistema e privacidade
echo Ajustando políticas de sistema e privacidade...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f

:: Desabilita sugestão automática na barra de endereço
echo Desabilitando sugestão automática na barra de endereço...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Explorer\AutoComplete" /v "AutoSuggest" /t REG_SZ /d "no" /f

:: Desabilita recursos de conteúdo e anúncios do Windows
echo Desabilitando recursos de conteúdo e anúncios do Windows...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f

:: Desabilita atualizações do Search Companion
echo Desabilitando atualizações do Search Companion...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SearchCompanion" /v "DisableContentFileUpdates" /t REG_DWORD /d 1 /f

:: Configurações de relatórios de erros do PCHealth
echo Ajustando relatórios de erro do PCHealth...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoSecondLevelCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoFileCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\PCHealth\ErrorReporting\DW" /v "DWNoExternalURL" /t REG_DWORD /d 1 /f

:: Desabilita Active Help do Windows
echo Desabilitando Active Help do Windows...
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoActiveHelp" /t REG_DWORD /d 1 /f

:: Desativa User Access Reporting do AppCompat
echo :Desativa User Access Reporting do AppCompat:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f

:: Desativa inventário do AppCompat
echo :Desativa inventário do AppCompat:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f

:: Desativa Application Impact Telemetry do AppCompat
echo :Desativa Application Impact Telemetry do AppCompat:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f

:: Desativa Experiência do Cliente (CEIP) da Microsoft
echo :Desativa Experiência do Cliente (CEIP) da Microsoft:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f

:: Redireciona URL do CEIP corporativo
echo :Redireciona URL do CEIP corporativo:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\SQMClient" /v "CorporateSQMURL" /t REG_SZ /d 127.0.0.1 /f

:: Desativa oferta do MRT via Windows Update
echo :Desativa oferta do MRT via Windows Update:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f

:: Desativa canais de eventos de telemetria e compatibilidade
echo :Desativa canais de eventos de telemetria e compatibilidade:
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Steps-Recorder" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Telemetry" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Inventory" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Troubleshooter" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Trace" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Compatibility-Infrastructure-Debug" /v "Enabled" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant/Analytic" /v "Enabled" /t REG_DWORD /d 0 /f 
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Application-Experience/Program-Compatibility-Assistant" /v "Enabled" /t REG_DWORD /d 0 /f 

:: Desativa Telemetria do Windows
echo :Desativa Telemetria do Windows:
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f

:: Impede coleta de metadados de dispositivos
echo :Impede coleta de metadados de dispositivos:
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f

:: Desativa telemetria da Cortana
echo :Desativa telemetria da Cortana:
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-inter_58073761d33f144b" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry-event_8ac43a41e5030538" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!proactive-telemetry.js" /t REG_DWORD /d 0 /f
REG ADD "HKLM\COMPONENTS\DerivedData\Components\amd64_microsoft-windows-c..lemetry.lib.cortana_31bf3856ad364e35_10.0.10240.16384_none_40ba2ec3d03bceb0" /v "f!dss-winrt-telemetry.js" /t REG_DWORD /d 0 /f

:: Marca RunOnce do IE como concluído
echo :Marca RunOnce do IE como concluído:
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f

:: Desativa Cortana
echo :Desativa Cortana:
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaEnabled" /t REG_DWORD /d 0 /f

:: Desativa inicialização automática de coletores de log WMI
echo :Desativa inicialização automática de coletores de log WMI:
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WdiContextLog" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\UBPM" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\TCPIPLOGGER" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\ReadyBoot" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\NtfsLog" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\LwtNetLog" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceUnlock" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\FaceRecoTel" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-System" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\EventLog-Security" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Circular Kernel Context Logger" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Audio" /v "Start" /t REG_DWORD /d 0 /f
REG ADD "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AppModel" /v "Start" /t REG_DWORD /d 0 /f

:: Desativa Preview Builds e experimentações do Windows
echo :Desativa Preview Builds e experimentações do Windows:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "AllowBuildPreview" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableConfigFlighting" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\PreviewBuilds" /v "EnableExperimentation" /t REG_DWORD /d 0 /f

:: Configura Prefetcher do Windows
echo :Configura Prefetcher do Windows:
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d %Prefetch% /f

:: Desativa adiamento de upgrade do Windows Update
echo :Desativa adiamento de upgrade do Windows Update:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d 0 /f

:: Remove tela de bloqueio
echo :Remove tela de bloqueio:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreen" /t REG_DWORD /d 1 /f

:: Desativa sondagem ativa do indicador de conectividade de rede
echo :Desativa sondagem ativa do indicador de conectividade de rede:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d 1 /f

:: Desativa download e atualização automática de mapas
echo :Desativa download e atualização automática de mapas:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Maps" /v "AutoDownloadAndUpdateMapData" /t REG_DWORD /d 0 /f

:: Desativa localização do Windows
echo :Desativa localização do Windows:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f

:: Desativa download automático de informações de jogos
echo :Desativa download automático de informações de jogos:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameUX" /v "DownloadGameInfo" /t REG_DWORD /d 0 /f

:: Desativa o File History
echo :Desativa o File History:
REG ADD "HKLM\Software\Policies\Microsoft\Windows\FileHistory" /v "Disabled" /t REG_DWORD /d "1" /f

:: Configura privacidade de aplicativos
echo :Configura privacidade de aplicativos:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d %ACCESSMICROPHONE% /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f

:: Desativa proteção antimalware do Windows Defender
echo :Desativa proteção antimalware do Windows Defender:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f

:: Desativa CEIP do Messenger
echo :Desativa CEIP do Messenger:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f

:: Restringe coleta de texto e tinta pelos aplicativos
echo :Restringe coleta de texto e tinta pelos aplicativos:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f

:: Configura Delivery Optimization para não baixar atualizações de outros PCs
echo :Configura Delivery Optimization para não baixar atualizações de outros PCs:
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DownloadMode" /t REG_DWORD /d 0 /f

:: Marca RunOnce do IE como concluído
echo :Marca RunOnce do IE como concluído:
REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f

:: Impede o Windows Media Player de buscar metadados de músicas
echo :Impede o Windows Media Player de buscar metadados de músicas:
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\WindowsMediaPlayer" /v "PreventMusicFileMetadataRetrieval" /t REG_DWORD /d 1 /f

:: Desativa notificações push de aplicativos
echo :Desativa notificações push de aplicativos:
REG ADD "HKCU\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoToastApplicationNotification" /t REG_DWORD /d "1" /f

:: Desativa CEIP do Messenger para usuário atual
echo :Desativa CEIP do Messenger para usuário atual:
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Messenger\Client" /v "CEIP" /t REG_DWORD /d 2 /f

:: Marca RunOnce do IE como concluído para usuário atual
echo :Marca RunOnce do IE como concluído para usuário atual:
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f

:: Restringe coleta de texto e tinta pelos aplicativos para usuário atual
echo :Restringe coleta de texto e tinta pelos aplicativos para usuário atual:
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 1 /f

:: Desativa SoftLanding do Content Delivery Manager
echo :Desativa SoftLanding do Content Delivery Manager:
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f

:: Define página inicial e busca do IE para Google
echo :Define página inicial e busca do IE para Google:
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Start Page Redirect Cache" /t REG_SZ /d "http://www.google.com" /f
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "Search Page" /t REG_SZ /d "http://www.google.com" /f

:: Marca RunOnce do IE como concluído para usuário atual
echo :Marca RunOnce do IE como concluído para usuário atual:
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceHasShown" /t REG_DWORD /d 1 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "RunOnceComplete" /t REG_DWORD /d 1 /f

:: Ativa Do Not Track no IE
echo :Ativa Do Not Track no IE:
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DoNotTrack" /t REG_DWORD /d 1 /f

:: Desativa personalização inicial do Internet Explorer
echo :Desativa personalização inicial do Internet Explorer:
REG ADD "HKCU\SOFTWARE\Microsoft\Internet Explorer\Main" /v "DisableFirstRunCustomize" /t REG_DWORD /d 1 /f

:: Desativa opção de obter ajuda via Assistência Remota
echo :Desativa opção de obter ajuda via Assistência Remota:
REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f

:: Desativa controle total via Assistência Remota
echo :Desativa controle total via Assistência Remota:
REG ADD "HKLM\System\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d "0" /f

:: Bloqueia conexões de Área de Trabalho Remota (RDP)
echo :Bloqueia conexões de Área de Trabalho Remota (RDP):
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fDenyTSConnections" /t REG_DWORD /d "1" /f

:: Desativa controle não solicitado via Terminal Services
echo :Desativa controle não solicitado via Terminal Services:
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicitedFullControl" /t REG_DWORD /d "0" /f

:: Desativa acesso não solicitado via Terminal Services
echo :Desativa acesso não solicitado via Terminal Services:
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowUnsolicited" /t REG_DWORD /d "0" /f

:: Desativa opção de obter ajuda via Terminal Services
echo :Desativa opção de obter ajuda via Terminal Services:
REG ADD "HKLM\Software\Policies\Microsoft\Windows NT\Terminal Services" /v "fAllowToGetHelp" /t REG_DWORD /d "0" /f

:: Desativa sincronização de configurações do Windows
echo :Desativa sincronização de configurações do Windows:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWindowsSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableWebBrowserSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSyncOnPaidNetwork" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableStartLayoutSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisablePersonalizationSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableDesktopThemeSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableCredentialsSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableAppSyncSettingSync" /t REG_DWORD /d 2 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSyncUserOverride" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableApplicationSettingSync" /t REG_DWORD /d 2 /f

:: Desativa uso da câmera na tela de bloqueio
echo :Desativa uso da câmera na tela de bloqueio:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f

:: Desativa revelação de senha na CredUI
echo :Desativa revelação de senha na CredUI:
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f

:: Bloqueia uso de imagem como senha em domínios
echo :Bloqueia uso de imagem como senha em domínios:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "BlockDomainPicturePassword" /t REG_DWORD /d 1 /f

:: Impede compartilhamento de dados de escrita à mão (Tablet PC)
echo :Impede compartilhamento de dados de escrita à mão (Tablet PC):
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f

:: Desativa busca web do Windows Search
echo :Desativa busca web do Windows Search:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f

:: Desativa busca conectada do Windows Search
echo :Desativa busca conectada do Windows Search:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f

:: Configura SafeSearch e privacidade para buscas conectadas
echo :Configura SafeSearch e privacidade para buscas conectadas:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchSafeSearch" /t REG_DWORD /d 3 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchPrivacy" /t REG_DWORD /d 3 /f

:: Impede buscas que usam localização
echo :Impede buscas que usam localização:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f

:: Desativa Bing na busca do Windows
echo :Desativa Bing na busca do Windows:
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f

:: Desativa notificações de feedback do Windows
echo :Desativa notificações de feedback do Windows:
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DoNotShowFeedbackNotifications" /t REG_DWORD /d 1 /f

:: Impede notificações de feedback do SIUF
echo :Impede notificações de feedback do SIUF:
REG ADD "HKCU\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f

:: Desativa feedback explícito do Assistente
echo :Desativa feedback explícito do Assistente:
REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Assistance\Client\1.0" /v "NoExplicitFeedback" /t REG_DWORD /d 1 /f

:: Desativa envio de dados para Spynet no Windows Defender
echo :Desativa envio de dados para Spynet no Windows Defender:
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v " SpyNetReporting" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Microsoft\Windows Defender\Spynet" /v " SubmitSamplesConsent" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f

:: Desativa sincronização de mensagens do Windows
echo :Desativa sincronização de mensagens do Windows:
reg add "HKLM\Software\Policies\Microsoft\Windows\Messaging" /v "AllowMessageSync" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Bloqueia acesso à informação de conta de usuário
echo :Bloqueia acesso à informação de conta de usuário:
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f 1>NUL 2>NUL

:: Configura política de sincronização de configurações do usuário
echo :Configura política de sincronização de configurações do usuário:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f 1>NUL 2>NUL

:: Remove fundo acrílico da tela de logon
echo :Remove fundo acrílico da tela de logon:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d "1" /f 1>NUL 2>NUL

:: Desativa identificador de publicidade do sistema e usuário
echo :Desativa identificador de publicidade do sistema e usuário:
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa dicas online do Explorer
echo :Desativa dicas online do Explorer:
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa sugestões de aplicativos recomendados pelo Windows
echo :Desativa sugestões de aplicativos recomendados pelo Windows:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "22StokedOnIt.NotebookPro_ffs55s3hze5sr" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "2FE3CB00.PicsArt-PhotoStudio_crhqpqs3x1ygc" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /v "41038Axilesoft.ACGMediaPlayer_wxjjre7dryqb6" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
rem ... (Repita para todas as entradas de SuggestedApps, conforme acima)

:: Desativa conteúdos e recursos do Content Delivery Manager
echo :Desativa conteúdos e recursos do Content Delivery Manager:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RemediationRequired" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa imagens rotativas da tela de bloqueio
echo :Desativa imagens rotativas da tela de bloqueio:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa sobreposições nas imagens rotativas da tela de bloqueio
echo :Desativa sobreposições nas imagens rotativas da tela de bloqueio:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa instalação silenciosa de aplicativos sugeridos
echo :Desativa instalação silenciosa de aplicativos sugeridos:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa SoftLanding do Content Delivery Manager
echo :Desativa SoftLanding do Content Delivery Manager:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa conteúdos assinados e sugestões do Windows
echo :Desativa conteúdos assinados e sugestões do Windows:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa sugestões no painel do sistema
echo :Desativa sugestões no painel do sistema:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa SmartScreen do sistema
echo :Desativa SmartScreen do sistema:
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T REG_DWORD /D 0 /F

:: Desativa animação do primeiro logon
echo :Desativa animação do primeiro logon:
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d "0" /f 1>NUL 2>NUL

:: Desativa serviços relacionados ao Windows Defender
echo :Desativa serviços relacionados ao Windows Defender:
reg add "HKLM\System\CurrentControlSet\Services\MDCoreSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdFilter" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisDrv" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WdNisSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d "4" /f

:: Desativa funcionalidades e notificações do Windows Defender
echo :Desativa funcionalidades e notificações do Windows Defender:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t "REG_DWORD" /d "1" /f
reg add "HKLM\Software\Microsoft\Windows Defender Security Center\Notifications" /v "DisableNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender Security Center\Notifications" /v "DisableEnhancedNotifications " /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativa inicialização rápida do Windows Defender
echo :Desativa inicialização rápida do Windows Defender:
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "AllowFastServiceStartup" /t REG_DWORD /d "0" /f

:: Desativa proteção em tempo real do Windows Defender
echo :Desativa proteção em tempo real do Windows Defender:
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableAntiVirus" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "DisableSpecialRunningModes" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\MpEngine" /v "MpEnablePus" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRoutinelyTakingAction" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\Reporting" /v "DisableEnhancedNotifications" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "DisableBlockAtFirstSeen" /t REG_DWORD /d "1" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SpynetReporting" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows Defender\SpyNet" /v "SubmitSamplesConsent" /t REG_DWORD /d "2" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f

:: Desativa sonda ativa do indicador de conectividade de rede
echo :Desativa sonda ativa do indicador de conectividade de rede:
reg add "HKLM\Software\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator" /v "NoActiveProbe" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\NlaSvc\Parameters\Internet" /v "EnableActiveProbing" /t REG_DWORD /d "0" /f

:: Desativa serviços de atualização e manutenção do Windows
echo :Desativa serviços de atualização e manutenção do Windows:
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\DoSvc" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\InstallService" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\UsoSvc" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\wuauserv" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\BITS" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\upfc" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\uhssvc" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\ossrs" /v Start /t reg_dword /d 4 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DisableWindowsUpdateAccess" /t REG_DWORD /d "1" /f
reg add "HKLM\System\CurrentControlSet\Services\PimIndexMaintenanceSvc" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d "4" /fd
reg add "HKLM\System\CurrentControlSet\Services\BcastDVRUserService" /v "Start" /t REG_DWORD /d "4" /f
reg add "HKLM\System\CurrentControlSet\Services\xbgm" /v "Start" /t REG_DWORD /d "4" /f

:: Desativa funcionalidades do GameDVR e GameBar
echo :Desativa funcionalidades do GameDVR e GameBar:
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "AudioCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "CursorCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v "MicrophoneCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_FSEBehavior" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_HonorUserFSEBehaviorMode" /t REG_DWORD /d "2" /f
reg add "HKCU\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f

:: Desativa GameDVR no Windows
echo :Desativa GameDVR no Windows:
reg add "HKLM\Software\Policies\Microsoft\Windows\GameDVR" /v "AllowgameDVR" /t REG_DWORD /d "0" /f

:: Desativa modo automático do GameBar
echo :Desativa modo automático do GameBar:
reg add "HKCU\Software\Microsoft\GameBar" /v "AutoGameModeEnabled" /t REG_DWORD /d "0" /f

:: Ajusta parâmetros de cache DNS
echo :Ajusta parâmetros de cache DNS:
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableBucketSize" /t REG_DWORD /d 1024 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "CacheHashTableSize" /t REG_DWORD /d 65536 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" /v "MaxCacheEntryTtlLimit" /t REG_DWORD /d 14400 /f

:: Desativa Power Throttling
echo :Desativa Power Throttling:
Reg add "HKLM\SYSTEM\CurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

:: Bloqueia acesso e atualizações do Windows Update
echo :Bloqueia acesso e atualizações do Windows Update:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DoNotConnectToWindowsUpdateInternetLocations" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "SetDisableUXWUAccess" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f

:: Ajusta threshold do SvcHostSplit
echo :Ajusta threshold do SvcHostSplit:
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "SvcHostSplitThresholdInKB" /t REG_DWORD /d "376926742" /f

:: Desativa serviço de atualização automática do Windows Update (wuauserv)
echo :Desativa serviço de atualização automática do Windows Update (wuauserv):
Reg add "HKLM\SYSTEM\ControlSet001\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f
Reg add "HKLM\SYSTEM\CurrentControlSet\Services\wuauserv" /v "Start" /t REG_DWORD /d "4" /f

:: Ajusta opções de atualização automática para Windows de 32bits
echo :Ajusta opções de atualização automática para Windows de 32bits:
Reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /t REG_DWORD /d "2" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallDay" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "ScheduledInstallTime" /t REG_DWORD /d "3" /f

:: Impede reinicialização automática com usuários logados
echo :Impede reinicialização automática com usuários logados:
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f

:: Configura Delivery Optimization para não baixar de outros PCs
echo :Configura Delivery Optimization para não baixar de outros PCs:
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f
Reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v "SystemSettingsDownloadMode" /t REG_DWORD /d "0" /f

:: Ajusta opções de adiamento de atualização do Windows
echo :Ajusta opções de adiamento de atualização do Windows:
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgrade" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpgradePeriod" /t REG_DWORD /d "1" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" /v "DeferUpdatePeriod" /t REG_DWORD /d "0" /f
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\UX\Settings" /v "DeferUpgrade" /t REG_DWORD /d "0" /f

:: Desativa atualizações do modelo de voz do Windows Speech
echo :Desativa atualizações do modelo de voz do Windows Speech:
Reg add "HKLM\SOFTWARE\Policies\Microsoft\Speech" /v "AllowSpeechModelUpdate" /t REG_DWORD /d "0" /f

:: Impede coleta de metadados de dispositivos
echo :Impede coleta de metadados de dispositivos:
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v "PreventDeviceMetadataFromNetwork" /t REG_DWORD /d "1" /f

:: Configura modo de download automático da Windows Store
echo :Configura modo de download automático da Windows Store:
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f

:: Impede registro de serviços do Windows Update
echo :Impede registro de serviços do Windows Update:
Reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Services\7971f918-a847-4430-9279-4a52d1efe18d" /v "RegisteredWithAU" /t REG_DWORD /d "0" /f

:: Ajusta prioridade de CPU para aplicativos/jogos
echo :Ajusta prioridade de CPU para aplicativos/jogos:
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\cof.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\csgo.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DarkSoulsIII.exe\PerfOptions" /v "CpuPriorityClass" /t REG_DWORD /d 3 /f
rem ... (Repita para demais jogos/aplicativos da lista acima)

:: Ajusta opções de atualização automática do Windows Update
echo :Ajusta opções de atualização automática do Windows Update:
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AUOptions" /d 2 /t REG_DWORD /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AutoInstallMinorUpdates" /d 0 /t REG_DWORD /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /d 1 /t REG_DWORD /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /d 1 /t REG_DWORD /f

:: Ajusta configurações visuais e animações da área de trabalho
echo :Ajusta configurações visuais e animações da área de trabalho:
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9012038010000000 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM " /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "IconsOnly" /T REG_DWORD /D 1 /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewAlphaSelect" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DragFullWindows" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewShadow" /T REG_DWORD /D 1 /F

@echo off

:: Desativa protetor de tela via política
echo :Desativa protetor de tela via política:
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /V "ScreenSaveActive" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /V "ScreenSaveActive" /T REG_DWORD /D 0 /F

:: Desativa coletor de log de telemetria (Diagtrack)
echo :Desativa coletor de log de telemetria (Diagtrack):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener\" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f

:: Desativa telemetria e coleta de dados
echo :Desativa telemetria e coleta de dados:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f > NUL 2>&1

:: Desativa texto de erro de diagnóstico na tela inicial do Windows Insider
echo :Desativa texto de erro de diagnóstico na tela inicial do Windows Insider:
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Visibility\" /v "DiagnosticErrorText" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\" /v "DiagnosticErrorText" /t REG_SZ /d "" /f
reg add "HKLM\SOFTWARE\Microsoft\WindowsSelfHost\UI\Strings\" /v "DiagnosticLinkText" /t REG_SZ /d "" /f

:: Impede coleta de metadados de dispositivos
echo :Impede coleta de metadados de dispositivos:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f

:: Desativa oferta do MRT via Windows Update
echo :Desativa oferta do MRT via Windows Update:
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f

:: Desativa Experiência do Cliente (CEIP)
echo :Desativa Experiência do Cliente (CEIP):
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f

:: Desativa Application Impact Telemetry e User Access Reporting
echo :Desativa Application Impact Telemetry e User Access Reporting:
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f

:: Desativa coletor de log de telemetria (SQMLogger)
echo :Desativa coletor de log de telemetria (SQMLogger):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

:: Impede tratamento de portas SATA como internas (AHCI)
echo :Impede tratamento de portas SATA como internas (AHCI):
reg add "HKLM\SYSTEM\CurrentControlSet\Services\storahci\Parameters\Device" /f /v TreatAsInternalPort /t REG_MULTI_SZ /d 0

:: Desativa logs de rede e setup (LwtNetLog, SetupPlatform)
echo :Desativa logs de rede e setup (LwtNetLog, SetupPlatform):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\LwtNetLog\{...}" /v "Enabled" /t REG_DWORD /d "0" /f
rem (Repita para todos os GUIDs listados acima)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SetupPlatform\{...}" /v "Enabled" /t REG_DWORD /d "0" /f
rem (Repita para todos os GUIDs listados acima)

:: Desativa logs de spooler (impressão)
echo :Desativa logs de spooler (impressão):
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\SpoolerLogger\{...}" /v "Enabled" /t REG_DWORD /d "0" /f
rem (Repita para todos os GUIDs listados acima)

:: Desativa logs de sessão Wi-Fi
echo :Desativa logs de sessão Wi-Fi:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{...}" /v "Enabled" /t REG_DWORD /d "0" /f
rem (Repita para todos os GUIDs listados acima)

:: Desativa logs WiFiSession (WMI Autologger)
echo Desativa logs WiFiSession (WMI Autologger)...

:: Desativando log geral de Wi-Fi.
echo Desativando log geral de Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{6eb8db94-fe96-443f-a366-5fe0cee7fb1c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de conectividade Wi-Fi.
echo Desativando log de conectividade Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{7D7180B3-A452-4FFF-8D1F-7B32B248AB70}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de rede Wi-Fi.
echo Desativando log de diagnóstico de rede Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{802ec45b-1e99-4b83-9920-87c98277ba9d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho Wi-Fi.
echo Desativando log de desempenho Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{814182FF-58F7-11E1-853C-78E7D1CA7337}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de segurança Wi-Fi.
echo Desativando log de eventos de segurança Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{90BBBABB-255B-4FE3-A06F-685A15E93A4C}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de driver Wi-Fi.
echo Desativando log de driver Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{914598a6-28f0-42ac-bf3d-a29c6047a739}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de autenticação Wi-Fi.
echo Desativando log de autenticação Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{949D7457-6151-4FA0-9E46-D82A6F9927CF}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização rápida Wi-Fi.
echo Desativando log de inicialização rápida Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de perfil Wi-Fi.
echo Desativando log de gerenciamento de perfil Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{999AC137-42DC-41D3-BA9D-A325A9E1A986}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rádio Wi-Fi.
echo Desativando log de rádio Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9B322459-4AD9-4F81-8EEA-DC77CDD18CA6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de roaming Wi-Fi.
echo Desativando log de roaming Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9B694F87-000E-4BE6-91AC-FE2E50D61A6F}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço WLAN.
echo Desativando log de serviço WLAN.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9CC0413E-5717-4af5-82EB-6103D8707B45}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de escaneamento Wi-Fi.
echo Desativando log de escaneamento Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{9CC9BEB7-9D24-47C7-8F9D-CCC9DCAC29EB}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de adaptadores Wi-Fi.
echo Desativando log de adaptadores Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{AB0D8EF9-866D-4d39-B83F-453F3B8F6325}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de Wi-Fi.
echo Desativando log de eventos de Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{abe47285-c002-46d1-95e4-c4aec3c78f50}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de driver de rede sem fio.
echo Desativando log de driver de rede sem fio.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{B8794785-F7E3-4C2D-A33D-7B0BA0D30E18}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de conectividade de rede sem fio.
echo Desativando log de conectividade de rede sem fio.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{c02edc8d-d627-46c9-abd9-c8b78f88c223}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de conexões Wi-Fi.
echo Desativando log de gerenciamento de conexões Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{C100BECE-D33A-4A4B-BF23-BBEF4663D017}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de Wi-Fi.
echo Desativando log de diagnósticos de Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{c7491fe4-66f4-4421-9954-b55f03db3186}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de WLAN AutoConfig.
echo Desativando log de eventos de WLAN AutoConfig.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{D28262A1-8066-492D-BCE8-635DA75368B7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de Telemetria Wi-Fi.
echo Desativando log de Telemetria Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{E5C16D49-2464-4382-BB20-97A4B5465DB9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de conectividade Wi-Fi.
echo Desativando log de diagnósticos de conectividade Wi-Fi.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\{e6dec100-4e0f-4927-92be-e69d7c15c821}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativa logs EventLog-System (WMI Autologger)
echo Desativa logs EventLog-System (WMI Autologger)...

:: Desativando log de diagnóstico de rede.
echo Desativando log de diagnóstico de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{01979c6a-42fa-414c-b8aa-eee2c8202018}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de componentes.
echo Desativando log de telemetria de componentes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{04268430-d489-424d-b914-0cff741d6684}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de rede.
echo Desativando log de serviço de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{059f0f37-910e-4ff0-a7ee-ae8d49dd319b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de sistema.
echo Desativando log de eventos de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{05f02597-fe85-4e67-8542-69567ab8fd4f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de dispositivos.
echo Desativando log de telemetria de dispositivos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (componentes).
echo Desativando log de sistema (componentes).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{0b886108-1899-4d3a-9c0d-42d8fc4b9108}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de inicialização.
echo Desativando log de telemetria de inicialização.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{0b9fdccc-451c-449c-9bd8-6756fcc6091a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia.
echo Desativando log de gerenciamento de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{0bf2fb94-7b60-4b4d-9766-e82f658df540}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de atividades do usuário.
echo Desativando log de atividades do usuário.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{0c478c5b-0351-41b1-8c58-4a6737da32e3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de hardware.
echo Desativando log de diagnóstico de hardware.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{0d4fdc09-8c27-494a-bda0-505e4fd8adae}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de software.
echo Desativando log de telemetria de software.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{0f67e49f-fe51-4e9f-b490-6f2948cc6027}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de rede).
echo Desativando log de sistema (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{0fa2ee03-1feb-5057-3bb3-eb25521b8482}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de componentes de segurança.
echo Desativando log de componentes de segurança.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{11c5d8ad-756a-42c2-8087-eb1b4a72a846}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de virtualização/Hyper-V.
echo Desativando log de virtualização/Hyper-V.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de drivers).
echo Desativando log de sistema (eventos de drivers).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{125f2cf1-2768-4d33-976e-527137d080f8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de dados.
echo Desativando log de telemetria de dados.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{15a7a4f8-0072-4eab-abad-f98a4d666aed}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho de rede.
echo Desativando log de desempenho de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{15ca44ff-4d7a-4baa-bba5-0998955e531e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de segurança de componentes.
echo Desativando log de segurança de componentes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{199fe037-2b82-40a9-82ac-e1d46c792b99}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de sistema (variados).
echo Desativando log de eventos de sistema (variados).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1b562e86-b7aa-4131-badc-b6f3a001407e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização/boot.
echo Desativando log de inicialização/boot.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1b6b0772-251b-4d42-917d-faca166bc059}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de software.
echo Desativando log de diagnósticos de software.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1c95126e-7eea-49a9-a3fe-a378b03ddb4d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços de gerenciamento.
echo Desativando log de serviços de gerenciamento.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1db28f2e-8f80-4027-8c5a-a11f7f10f62d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de rede.
echo Desativando log de telemetria de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1e9a4978-78c2-441e-8858-75b5d1326bc5}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de energia.
echo Desativando log de diagnósticos de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{1f678132-5938-4686-9fdc-c8ff68f15c85}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de dispositivos.
echo Desativando log de gerenciamento de dispositivos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{206f6dea-d3c5-4d10-bc72-989f03c8b84b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{21b7c16e-c5af-4a69-a74a-7245481c1b97}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (configuração).
echo Desativando log de sistema (configuração).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{2a274310-42d5-4019-b816-e4b8c7abe95c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de desempenho.
echo Desativando log de diagnósticos de desempenho.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{2e35aaeb-857f-4beb-a418-2e6c0e54d988}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de rede).
echo Desativando log de sistema (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{2e6cb42e-161d-413b-a6c1-84ca4c1e5890}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de agendador de tarefas.
echo Desativando log de agendador de tarefas.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{2f07e2ee-15db-40f1-90ef-9d7ba282188a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de sistema.
echo Desativando log de serviço de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{2ff3e6b7-cb90-4700-9621-443f389734ed}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização de processos.
echo Desativando log de inicialização de processos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{306c4e0b-e148-543d-315b-c618eb93157c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de sistema.
echo Desativando log de telemetria de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{30e1d284-5d88-459c-83fd-6345b39b19ec}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos/compatibilidade.
echo Desativando log de aplicativos/compatibilidade.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{331c3b3a-2005-44c2-ac5e-77220c37d6b4}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de dispositivo.
echo Desativando log de diagnósticos de dispositivo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{355c44fe-0c8e-4bf8-be28-8bc7b5a42720}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de kernel).
echo Desativando log de sistema (eventos de kernel).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{3629dd4d-d6f1-4302-a623-0768b51501c7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de PnP (Plug and Play).
echo Desativando log de PnP (Plug and Play).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{36c23e18-0e66-11d9-bbeb-505054503030}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de sistema.
echo Desativando log de diagnóstico de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{3903d5b9-988d-4c31-9ccd-4022f96703f0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de rede.
echo Desativando log de telemetria de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{3cb2a168-fe19-4a4e-bdad-dcf422f13473}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (sessões de logon).
echo Desativando log de sistema (sessões de logon).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{3e59a529-b0b3-4a11-8129-9ffe6bb46eb9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de atualização.
echo Desativando log de serviço de atualização.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{3f471139-acb7-4a01-b7a7-ff5da4ba2d43}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de segurança de processos.
echo Desativando log de segurança de processos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{3ff37a1c-a68d-4d6e-8c9b-f79e8b16c482}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de sistema.
echo Desativando log de telemetria de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{40783728-8921-45d0-b231-919037b4b4fd}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de rede).
echo Desativando log de sistema (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{412bdff2-a8c4-470d-8f33-63fe0d8c20e2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de hardware.
echo Desativando log de telemetria de hardware.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{43e63da5-41d1-4fbf-aded-1bbed98fdd1d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços de kernel.
echo Desativando log de serviços de kernel.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{45eec9e5-4a1b-5446-7ad8-a4ab1313c437}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia.
echo Desativando log de gerenciamento de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{46c78e5c-a213-46a8-8a6b-622f6916201d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (diagnósticos).
echo Desativando log de sistema (diagnósticos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{47bc9477-a8ba-452e-b951-4f2ed3593cf9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de kernel).
echo Desativando log de sistema (eventos de kernel).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{47bfa2b7-bd54-4fac-b70b-29021084ca8f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de drivers de dispositivo.
echo Desativando log de drivers de dispositivo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{494e7a3d-8db9-4ec4-b43e-2844af6e38d6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de plataforma.
echo Desativando log de telemetria de plataforma.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{4af188ac-e9c4-4c11-b07b-1fabc07dfeb2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de software).
echo Desativando log de sistema (eventos de software).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{4cb314df-c11f-47d7-9c04-65fb0051561b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de desempenho.
echo Desativando log de telemetria de desempenho.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{4cec9c95-a65f-4591-b5c4-30100e51d870}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços de inicialização.
echo Desativando log de serviços de inicialização.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{4ee76bd8-3cf4-44a0-a0ac-3937643e37a3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rede (diagnósticos).
echo Desativando log de rede (diagnósticos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{52fc89f8-995e-434c-a91e-199986449890}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de energia.
echo Desativando log de diagnósticos de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{530fb9b9-c515-4472-9313-fb346f9255e3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de segurança.
echo Desativando log de telemetria de segurança.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{538cbbad-4877-4eb2-b26e-7caee8f0f8cb}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (serviços de rede).
echo Desativando log de sistema (serviços de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{54cb22ff-26b4-4393-a8c2-6b0715912c5f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de segurança.
echo Desativando log de eventos de segurança.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{555908d1-a6d7-4695-8e1e-26931d2012f4}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de experiência.
echo Desativando log de telemetria de experiência.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{55ab77f6-fa04-43ef-af45-688fbf500482}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos gerais).
echo Desativando log de sistema (eventos gerais).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{595f7f52-c90a-4026-a125-8eb5e083f15e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização (diagnósticos).
echo Desativando log de inicialização (diagnósticos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{5d674230-ca9f-11da-a94d-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de diagnóstico.
echo Desativando log de telemetria de diagnóstico.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{5d896912-022d-40aa-a3a8-4fa5515c76d7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de privacidade.
echo Desativando log de telemetria de privacidade.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{5f92bc59-248f-4111-86a9-e393e12c6139}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de rede).
echo Desativando log de sistema (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{62de9e48-90c6-4755-8813-6a7d655b0802}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando logs de sessão de EventLog-System
echo Desativando logs de sessão de EventLog-System...

:: Desativando log de sistema (componentes/boot).
echo Desativando log de sistema (componentes/boot).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{632f767e-0ec3-47b9-ba1c-a0e62a74728a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rede/conectividade.
echo Desativando log de rede/conectividade.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{63d1e632-95cc-4443-9312-af927761d52a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de BITS (Background Intelligent Transfer Service).
echo Desativando log de BITS (Background Intelligent Transfer Service).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{64ef2b1c-4ae1-4e64-8599-1636e441ec88}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia/ACPI.
echo Desativando log de gerenciamento de energia/ACPI.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{651df93b-5053-4d1e-94c5-f6e6d25908d0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria/compatibilidade de apps.
echo Desativando log de telemetria/compatibilidade de apps.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{66a5c15c-4f8e-4044-bf6e-71d896038977}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de áudio do sistema.
echo Desativando log de áudio do sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{67fe2216-727a-40cb-94b2-c02211edb34a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de performance/uso de recursos.
echo Desativando log de performance/uso de recursos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{6a1f2b00-6a90-4c38-95a5-5cab3b056778}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de falhas do sistema/crashes.
echo Desativando log de falhas do sistema/crashes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{6b93bf66-a922-4c11-a617-cf60d95c133d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de agendador de tarefas.
echo Desativando log de agendador de tarefas.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{6bba3851-2c7e-4dea-8f54-31e5afd029e3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de segurança/auditoria.
echo Desativando log de segurança/auditoria.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{7237fff9-a08a-4804-9c79-4a8704b70b87}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de Windows Update.
echo Desativando log de Windows Update.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{72cd9ff7-4af8-4b89-aede-5f26fda13567}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho/inicialização.
echo Desativando log de desempenho/inicialização.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{73a33ab2-1966-4999-8add-868c41415269}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de interface de usuário/shell.
echo Desativando log de interface de usuário/shell.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{73e9c9de-a148-41f7-b1db-4da051fdc327}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciador de janelas/gráficos.
echo Desativando log de gerenciador de janelas/gráficos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{74c2135f-cc76-45c3-879a-ef3bb1eeaf86}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de criptografia/certificados.
echo Desativando log de criptografia/certificados.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{75ebc33e-997f-49cf-b49f-ecc50184b75d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rastreamento de drivers/hardware.
echo Desativando log de rastreamento de drivers/hardware.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{7725b5f9-1f2e-4e21-baeb-b2af4690bc87}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos gerais).
echo Desativando log de sistema (eventos gerais).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{7b563579-53c8-44e7-8236-0f87b9fe6594}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rede sem fio/WLAN.
echo Desativando log de rede sem fio/WLAN.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{7b6bc78c-898b-4170-bbf8-1a469ea43fc5}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização do sistema/kernel.
echo Desativando log de inicialização do sistema/kernel.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{7d5387b0-cbe0-11da-a94d-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de armazenamento/disco.
echo Desativando log de armazenamento/disco.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{7da4fe0e-fd42-4708-9aa5-89b77a224885}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de firewall/segurança de rede.
echo Desativando log de firewall/segurança de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{85a62a0d-7e17-485f-9d4f-749a287193a6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de usuários/logon.
echo Desativando log de gerenciamento de usuários/logon.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{89203471-d554-47d4-bde4-7552ec219999}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de rede/conexões.
echo Desativando log de serviço de rede/conexões.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{89592015-d996-4636-8f61-066b5d4dd739}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de Windows Defender/segurança.
echo Desativando log de Windows Defender/segurança.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{89fe8f40-cdce-464e-8217-15ef97d4c7c3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços de infraestrutura.
echo Desativando log de serviços de infraestrutura.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{8c416c79-d49b-4f01-a467-e56d3aa8234c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (variados).
echo Desativando log de sistema (variados).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{8e6a5303-a4ce-498f-afdb-e03a8a82b077}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de componentes.
echo Desativando log de telemetria de componentes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{945a8954-c147-4acd-923f-40c45405a658}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de drivers/PnP.
echo Desativando log de drivers/PnP.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{951b41ea-c830-44dc-a671-e2c9958809b8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de kernel).
echo Desativando log de sistema (eventos de kernel).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{95353826-4fbe-41d4-9c42-f521c6e86360}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de inicialização rápida.
echo Desativando log de eventos de inicialização rápida.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de processos.
echo Desativando log de gerenciamento de processos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{96f4a050-7e31-453c-88be-9634f4e02139}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de desempenho.
echo Desativando log de telemetria de desempenho.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{9741fd4e-3757-479f-a3c6-fc49f6d5edd0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de registro de dispositivos.
echo Desativando log de registro de dispositivos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{988c59c5-0a1c-45b6-a555-0c62276e327d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos diversos).
echo Desativando log de sistema (eventos diversos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{991f8fe6-249d-44d6-b93d-5a3060c1dedb}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de Windows Hello/biometria.
echo Desativando log de Windows Hello/biometria.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{9988748e-c2e8-4054-85f6-0c3e1cad2470}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de AppX (aplicativos da loja).
echo Desativando log de AppX (aplicativos da loja).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{9c205a39-1250-487d-abd7-e831c6290539}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços de rede/DNS.
echo Desativando log de serviços de rede/DNS.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{9f650c63-9409-453c-a652-83d7185a2e83}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de inicialização.
echo Desativando log de telemetria de inicialização.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{9f7b5df4-b902-48bc-bc94-95068c6c7d26}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de energia).
echo Desativando log de sistema (eventos de energia).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{a0e3d8ea-c34f-4419-a1db-90435b8b21d0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de desempenho.
echo Desativando log de diagnóstico de desempenho.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{a4445c76-ed85-c8a3-02c1-532a38614a9e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de dispositivos.
echo Desativando log de gerenciamento de dispositivos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{a67075c2-3e39-4109-b6cd-6d750058a731}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de WMI Activity.
echo Desativando log de WMI Activity.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço BITS (Background Intelligent Transfer Service).
echo Desativando log de serviço BITS (Background Intelligent Transfer Service).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{a6ad76e3-867a-4635-91b3-4904ba6374d7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização de processos.
echo Desativando log de inicialização de processos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{a7f2235f-be51-51ed-decf-f4498812a9a2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de kernel).
echo Desativando log de sistema (eventos de kernel).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{a8a1f2f6-a13a-45e9-b1fe-3419569e5ef2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de energia/suspensão).
echo Desativando log de sistema (eventos de energia/suspensão).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{aa3aa23b-bb6d-425a-b58c-1d7e37f5d02a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia.
echo Desativando log de gerenciamento de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{abf1f586-2e50-4ba8-928d-49044e6f0db7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnósticos de rede.
echo Desativando log de diagnósticos de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ac43300d-5fcc-4800-8e99-1bd3f85f0320}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de gerenciamento de usuários.
echo Desativando log de serviço de gerenciamento de usuários.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ac52ad17-cc01-4f85-8df5-4dce4333c99b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho do sistema.
echo Desativando log de desempenho do sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ad5162d8-daf0-4a25-88a7-01cbeb33902e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos diversos).
echo Desativando log de sistema (eventos diversos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{aea1b4fa-97d1-45f2-a64c-4d69fffd92c9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de driver PNP.
echo Desativando log de driver PNP.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{aec5c129-7c10-407d-be97-91a042c61aaa}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de discos/volumes.
echo Desativando log de gerenciamento de discos/volumes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{b0aa8734-56f7-41cc-b2f4-de228e98b946}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho (diversos).
echo Desativando log de desempenho (diversos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{b2fcd41f-9a40-4150-8c92-b224b7d8c8aa}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços do Windows Update.
echo Desativando log de serviços do Windows Update.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{b675ec37-bdb6-4648-bc92-f3fdc74d3ca2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de áudio.
echo Desativando log de áudio.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{b977cf02-76f6-df84-cc1a-6a4b232322b6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização do sistema.
echo Desativando log de inicialização do sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{b99317e5-89b7-4c0d-abd1-6e705f7912dc}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de aplicativos.
echo Desativando log de gerenciamento de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ba093605-3909-4345-990b-26b746adee0a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de rede).
echo Desativando log de sistema (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ba2ffb5c-e20a-4fb9-91b4-45f61b4b66a0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de componentes da interface.
echo Desativando log de componentes da interface.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{babda89a-4d5e-48eb-af3d-e0e8410207c0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de dispositivos USB.
echo Desativando log de dispositivos USB.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{bc0669e1-a10d-4a78-834e-1ca3c806c93b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho de rede.
echo Desativando log de desempenho de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{c02afc2b-e24e-4449-ad76-bcc2c2575ead}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de driver).
echo Desativando log de sistema (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{c03715ce-ea6f-5b67-4449-da1d1e1afeb8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização de software.
echo Desativando log de inicialização de software.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{c18672d1-dc18-4dfd-91e4-170cf37160cf}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de sistema.
echo Desativando log de eventos de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{c26c4f3c-3f66-4e99-8f8a-39405cfed220}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de hardware.
echo Desativando log de eventos de hardware.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{c4636a1e-7986-4646-bf10-7bc3b4a76e8e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de rede.
echo Desativando log de gerenciamento de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{c76baa63-ae81-421c-b425-340b4b24157f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho (variados).
echo Desativando log de desempenho (variados).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{c914f0df-835a-4a22-8c70-732c9a80c634}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia.
echo Desativando log de gerenciamento de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{cb017cd2-1f37-4e65-82bc-3e91f6a37559}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de drivers de dispositivo.
echo Desativando log de drivers de dispositivo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{cbda4dbf-8d5d-4f69-9578-be14aa540d22}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de drivers).
echo Desativando log de sistema (eventos de drivers).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{cd9c6198-bf73-4106-803b-c17d26559018}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia.
echo Desativando log de gerenciamento de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{cdc05e28-c449-49c6-b9d2-88cf761644df}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de inicialização).
echo Desativando log de sistema (eventos de inicialização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{cdead503-17f5-4a3e-b7ae-df8cc2902eb9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de segurança.
echo Desativando log de eventos de segurança.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ce8dee0b-d539-4000-b0f8-77bed049c590}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de componentes.
echo Desativando log de telemetria de componentes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{cfc18ec0-96b1-4eba-961b-622caee05b0a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de kernel).
echo Desativando log de sistema (eventos de kernel).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{d0e22efc-ac66-4b25-a72d-382736b5e940}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de rede.
echo Desativando log de serviço de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (diagnósticos).
echo Desativando log de sistema (diagnósticos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{d48ce617-33a2-4bc3-a5c7-11aa4f29619e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de desempenho.
echo Desativando log de telemetria de desempenho.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{d5c25f9a-4d47-493e-9184-40dd397a004d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de kernel/boot).
echo Desativando log de sistema (eventos de kernel/boot).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{d6f68875-cdf5-43a5-a3e3-53ffd683311c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia.
echo Desativando log de gerenciamento de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rede (diagnósticos).
echo Desativando log de rede (diagnósticos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{dd70bc80-ef44-421b-8ac3-cd31da613a4e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de componentes gráficos.
echo Desativando log de componentes gráficos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{de29cf61-5ee6-43ff-9aac-959c4e13cc6c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (diagnóstico de serviço).
echo Desativando log de sistema (diagnóstico de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de hardware.
echo Desativando log de telemetria de hardware.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{dea07764-0790-44de-b9c4-49677b17174f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rede (componentes).
echo Desativando log de rede (componentes).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e104fb41-6b04-4f3a-b47d-f0df2f02b954}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de criptografia/segurança.
echo Desativando log de criptografia/segurança.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e2816346-87f4-4f85-95c3-0c79409aa89d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de desempenho.
echo Desativando log de telemetria de desempenho.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e3bac9f8-27be-4823-8d7f-1cc320c05fa7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização de sistema (componentes).
echo Desativando log de inicialização de sistema (componentes).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e4480490-85b6-11dd-ad8b-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de dispositivos/PnP.
echo Desativando log de dispositivos/PnP.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e4f68870-5ae8-4e5b-9ce7-ca9ed75b0245}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (sessão de logon).
echo Desativando log de sistema (sessão de logon).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e595f735-b42a-494b-afcd-b68666945cd3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de conectividade de rede.
echo Desativando log de conectividade de rede.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e5ba83f6-07d0-46b1-8bc7-7e669a1d31dc}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (telemetria).
echo Desativando log de sistema (telemetria).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e670a5a2-ce74-4ab4-9347-61b815319f4c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de componentes.
echo Desativando log de telemetria de componentes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{e8f9af91-afbe-5a03-dfec-5d591686326c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (diagnóstico de rede).
echo Desativando log de sistema (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ea216962-877b-5b73-f7c5-8aef5375959e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de desempenho.
echo Desativando log de diagnóstico de desempenho.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{eee173ef-7ed2-45de-9877-01c70a852fbd}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de sistema (variados).
echo Desativando log de eventos de sistema (variados).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{ef1cc15b-46c1-414e-bb95-e76b077bd51e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de segurança de sistema.
echo Desativando log de segurança de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{f029ac39-38f0-4a40-b7de-404d244004cb}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (eventos de drivers).
echo Desativando log de sistema (eventos de drivers).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{f2e2ce31-0e8a-4e46-a03b-2e0fe97e93c2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de energia.
echo Desativando log de gerenciamento de energia.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{f3c5e28e-63f6-49c7-a204-e48a1bc4b09d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de plataforma.
echo Desativando log de telemetria de plataforma.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{f5d05b38-80a6-4653-825d-c414e4ab3c68}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização de sistema.
echo Desativando log de inicialização de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{f708c483-4880-11e6-9121-5cf37068b67b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de rede (monitoramento).
echo Desativando log de rede (monitoramento).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{f717d024-f5b4-4f03-9ab9-331b2dc38ffb}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de sistema.
echo Desativando log de serviço de sistema.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{f9fe3908-44b8-48d9-9a32-5a763ff5ed79}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de segurança (componentes).
echo Desativando log de segurança (componentes).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{fc4e8f51-7a04-4bab-8b91-6321416f72ab}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de sistema (gerenciamento).
echo Desativando log de sistema (gerenciamento).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de usuário.
echo Desativando log de telemetria de usuário.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-System\{fcbb06bb-6a2a-46e3-abaa-246cb4e508b2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (variados).
echo Desativando log de aplicativos (variados).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{01090065-b467-4503-9b28-533766761087}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de dispositivos.
echo Desativando log de telemetria de dispositivos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{06edcfeb-0fd0-4e53-acca-a6f8bbf81bcb}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de inicialização de aplicativos.
echo Desativando log de eventos de inicialização de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{08466062-aed4-4834-8b04-cddb414504e5}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de aplicativo.
echo Desativando log de diagnóstico de aplicativo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{0888e5ef-9b98-4695-979d-e92ce4247224}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (compatibilidade).
echo Desativando log de aplicativos (compatibilidade).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{09608c12-c1da-4104-a6fe-b959cf57560a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de instalação de aplicativos.
echo Desativando log de eventos de instalação de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{09ac07b9-6ac9-43bc-a50f-58419a797c69}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de segurança de aplicativos.
echo Desativando log de segurança de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{09ec9687-d7ad-40ca-9c5e-78a04a5ae993}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização de processos.
echo Desativando log de inicialização de processos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{0dd4d48e-2bbf-452f-a7ec-ba3dba8407ae}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de uso de aplicativos.
echo Desativando log de telemetria de uso de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{0ff1c24b-7f05-45c0-abdc-3c8521be4f62}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de erros de aplicativos.
echo Desativando log de erros de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{10a208dd-a372-421c-9d99-4fad6db68b62}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de desempenho de aplicativos.
echo Desativando log de desempenho de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1139c61b-b549-4251-8ed3-27250a1edec8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento).
echo Desativando log de aplicativos (gerenciamento).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{11a75546-3234-465e-bec8-2d301cb501ac}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de componentes de aplicativos.
echo Desativando log de telemetria de componentes de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{126cdb97-d346-4894-8a34-658da5eea1b6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de integridade de aplicativos.
echo Desativando log de integridade de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{134ea407-755d-4a93-b8a6-f290cd155023}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos gerais).
echo Desativando log de aplicativos (eventos gerais).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{13bc4371-4e21-4e46-a84f-8c0ffb548ced}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços de aplicativos.
echo Desativando log de serviços de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1418ef04-b0b4-4623-bf7e-d74ab47bbdaa}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de dados.
echo Desativando log de telemetria de dados.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{15a7a4f8-0072-4eab-abad-f98a4d666aed}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de segurança de aplicativos.
echo Desativando log de segurança de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1b8b402d-78dc-46fb-bf71-46e64aedf165}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (instalação/atualização).
echo Desativando log de aplicativos (instalação/atualização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1bda2ab1-bbc1-4acb-a849-c0ef2b249672}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviços de gerenciamento.
echo Desativando log de serviços de gerenciamento.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1db28f2e-8f80-4027-8c5a-a11f7f10f62d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de experiência de aplicativos.
echo Desativando log de telemetria de experiência de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1ed6976a-4171-4764-b415-7ea08bc46c51}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de erros de aplicativos.
echo Desativando log de erros de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{1edeee53-0afe-4609-b846-d8c0b2075b1f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de aplicativo.
echo Desativando log de diagnóstico de aplicativo.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{21d79db0-8e03-41cd-9589-f3ef7001a92a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (relatório de erros).
echo Desativando log de aplicativos (relatório de erros).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{23b8d46b-67dd-40a3-b636-d43e50552c6d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de uso).
echo Desativando log de aplicativos (eventos de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{27a8c1e2-eb19-463e-8424-b399df27a216}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de aplicativos.
echo Desativando log de gerenciamento de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{287d59b6-79ba-4741-a08b-2fedeede6435}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (cache).
echo Desativando log de aplicativos (cache).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{28aa95bb-d444-4719-a36f-40462168127e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de desempenho de aplicativos.
echo Desativando log de telemetria de desempenho de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{28e25b07-c47f-473d-8b24-2e171cca808a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de inicialização de aplicativos.
echo Desativando log de inicialização de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2a45d52e-bbf3-4843-8e18-b356ed5f6a65}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de AppX.
echo Desativando log de telemetria de AppX.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2a576b87-09a7-520e-c21a-4942f0271d67}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2cd58181-0bb6-463e-828a-056ff837f966}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de monitoramento de aplicativos.
echo Desativando log de monitoramento de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2d318b91-e6e7-4c46-bd04-bfe6db412cf9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (instalação de drivers).
echo Desativando log de aplicativos (instalação de drivers).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2ed299d2-2f6b-411d-8d15-f4cc6fde0c70}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (notificações).
echo Desativando log de aplicativos (notificações).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{2f94e1cc-a8c5-4fe7-a1c3-53d7bda8e73e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de aplicativos (sessão).
echo Desativando log de gerenciamento de aplicativos (sessão).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{30336ed4-e327-447c-9de0-51b652c86108}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (compatibilidade de hardware).
echo Desativando log de aplicativos (compatibilidade de hardware).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{314de49f-ce63-4779-ba2b-d616f6963a88}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de processos.
echo Desativando log de telemetria de processos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{315a8872-923e-4ea2-9889-33cd4754bf64}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{319122a9-1485-4e48-af35-7db2d93b8ad2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{32254f6c-aa33-46f0-a5e3-1cbcc74bf683}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (relatório de falhas).
echo Desativando log de aplicativos (relatório de falhas).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3527cb55-1298-49d4-ab94-1243db0fcaff}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de desempenho).
echo Desativando log de aplicativos (diagnóstico de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3663a992-84be-40ea-bba9-90c7ed544222}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de PnP (Plug and Play).
echo Desativando log de PnP (Plug and Play).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{36c23e18-0e66-11d9-bbeb-505054503030}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3a5bef13-d0f7-4e7f-9ec8-5e707df711d0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3a718a68-6974-4075-abd3-e8243caef398}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3aa52b8b-6357-4c18-a92e-b53fb177853b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (armazenamento).
echo Desativando log de aplicativos (armazenamento).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3ae1ea61-c002-47fb-b06c-4022a8c98929}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (instalação de software).
echo Desativando log de aplicativos (instalação de software).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3c088e51-65be-40d1-9b90-62bfec076737}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3cb40aaa-1145-4fb8-b27b-7e30f0454316}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (notificações).
echo Desativando log de aplicativos (notificações).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3cc2d4af-da5e-4ed4-bcbe-3cf995940483}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de desempenho).
echo Desativando log de aplicativos (diagnóstico de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3d42a67d-9ce8-4284-b755-2550672b0ce0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos gerais).
echo Desativando log de aplicativos (eventos gerais).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3da494e4-0fe2-415c-b895-fb5265c5c83b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de serviço de atualização.
echo Desativando log de serviço de atualização.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{3f471139-acb7-4a01-b7a7-ff5da4ba2d43}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de gerenciamento de aplicativos.
echo Desativando log de gerenciamento de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{40ab57c2-1c53-4df9-9324-ff7cf898a02c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (relatório de uso).
echo Desativando log de aplicativos (relatório de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{41862974-da3b-4f0b-97d5-bb29fbb9b71e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de registro).
echo Desativando log de aplicativos (eventos de registro).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{442c11c5-304b-45a4-ae73-dc2194c4e876}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de shell).
echo Desativando log de aplicativos (eventos de shell).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{46098845-8a94-442d-9095-366a6bcfefa9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de diagnóstico de aplicativo (erros).
echo Desativando log de diagnóstico de aplicativo (erros).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4a104570-ec6d-4560-a40f-858fa955e84f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativo (eventos de driver).
echo Desativando log de aplicativo (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4a933674-fb3d-4e8d-b01d-17ee14e91a3e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de telemetria de aplicativos.
echo Desativando log de eventos de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4cb314df-c11f-47d7-9c04-65fb0051561b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de serviço).
echo Desativando log de aplicativos (diagnóstico de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4de9bc9c-b27a-43c9-8994-0915f1a5e24f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{4eacb4d0-263b-4b93-8cd6-778a278e5642}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de desempenho de aplicativos.
echo Desativando log de telemetria de desempenho de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{50df9e12-a8c4-4939-b281-47e1325ba63e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (sessão de usuário).
echo Desativando log de aplicativos (sessão de usuário).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{50f99b2d-96d2-421f-be4c-222c4140da9f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (inicialização de processos).
echo Desativando log de aplicativos (inicialização de processos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{530fb9b9-c515-4472-9313-fb346f9255e3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de experiência de aplicativos.
echo Desativando log de telemetria de experiência de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5402e5ea-1bdd-4390-82be-e108f1e634f5}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos gerais).
echo Desativando log de aplicativos (eventos gerais).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{54164045-7c50-4905-963f-e5bc1eef0cca}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de integridade).
echo Desativando log de aplicativos (diagnóstico de integridade).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{57003e21-269b-4bdc-8434-b3bf8d57d2d5}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de componentes de aplicativos.
echo Desativando log de telemetria de componentes de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{579402a2-883c-45d8-b70a-9bc856407751}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento de memória).
echo Desativando log de aplicativos (gerenciamento de memória).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{58980f4b-bd39-4a3e-b344-492ed2254a4e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de logon).
echo Desativando log de aplicativos (eventos de logon).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{595f33ea-d4af-4f4d-b4dd-9dacdd17fc6e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5b0a651a-8807-45cc-9656-7579815b6af0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5b5ab841-7d2e-4a95-bb4f-095cdf66d8f0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de driver).
echo Desativando log de aplicativos (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5bbca4a8-b209-48dc-a8c7-b23d3e5216fb}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (configuração de PnP).
echo Desativando log de aplicativos (configuração de PnP).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5d674230-ca9f-11da-a94d-0800200c9a66}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de atualização).
echo Desativando log de aplicativos (eventos de atualização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5d896912-022d-40aa-a3a8-4fa5515c76d7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de registro).
echo Desativando log de aplicativos (eventos de registro).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5ec13d8e-4b3f-422e-a7e7-3121a1d90c7a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de processo).
echo Desativando log de aplicativos (eventos de processo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{5f0e257f-c224-43e5-9555-2adcb8540a58}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de serviço).
echo Desativando log de aplicativos (diagnóstico de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{63b530f8-29c9-4880-a5b4-b8179096e7b8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (compatibilidade de software).
echo Desativando log de aplicativos (compatibilidade de software).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{63d2bb1d-e39a-41b8-9a3d-52dd06677588}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de eventos de telemetria de aplicativos.
echo Desativando log de eventos de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6489b27f-7c43-5886-1d00-0a61bb2a375b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de driver).
echo Desativando log de aplicativos (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{64a98c25-9e00-404e-84ad-6700dfe02529}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento de sessão).
echo Desativando log de aplicativos (gerenciamento de sessão).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{64ef2b1c-4ae1-4e64-8599-1636e441ec88}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de processo).
echo Desativando log de aplicativos (diagnóstico de processo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{66a5c15c-4f8e-4044-bf6e-71d896038977}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{67d07935-283a-4791-8f8d-fa9117f3e6f2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de instalação).
echo Desativando log de aplicativos (telemetria de instalação).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{699e309c-e782-4400-98c8-e21d162d7b7b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento de energia).
echo Desativando log de aplicativos (gerenciamento de energia).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{69c8ca7e-1adf-472b-ba4c-a0485986b9f6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de segurança).
echo Desativando log de aplicativos (diagnóstico de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6a1f2b00-6a90-4c38-95a5-5cab3b056778}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de rede).
echo Desativando log de aplicativos (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6b1ffe48-5b1e-4793-9f7f-ae926454499d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6d7662a9-034e-4b1f-a167-67819c401632}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de tempo de execução).
echo Desativando log de aplicativos (eventos de tempo de execução).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6d8a3a60-40af-445a-98ca-99359e500146}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6df57621-e7e4-410f-a7e9-e43eeb61b11f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (instalação de componentes).
echo Desativando log de aplicativos (instalação de componentes).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6e400999-5b82-475f-b800-cef6fe361539}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (geral).
echo Desativando log de aplicativos (geral).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{6eb8db94-fe96-443f-a366-5fe0cee7fb1c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de telemetria).
echo Desativando log de aplicativos (eventos de telemetria).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{712abb2d-d806-4b42-9682-26da01d8b307}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de falhas).
echo Desativando log de aplicativos (diagnóstico de falhas).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{72561cf0-c85c-4f78-9e8d-cba9093df62d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (monitoramento de desempenho).
echo Desativando log de aplicativos (monitoramento de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{728b02d9-bf21-49f6-be3f-91bc06f7467e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{72d211e1-4c54-4a93-9520-4901681b2271}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de serviço).
echo Desativando log de aplicativos (eventos de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{73370bd6-85e5-430b-b60a-fea1285808a7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de cache).
echo Desativando log de aplicativos (eventos de cache).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{741bb90c-a7a3-49d6-bd82-1e6b858403f7}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de conectividade).
echo Desativando log de aplicativos (diagnóstico de conectividade).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{741fc222-44ed-4ba7-98e3-f405b2d2c4b4}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{747ef6fd-e535-4d16-b510-42c90f6873a1}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (subsistema).
echo Desativando log de telemetria de aplicativos (subsistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-0870-49e5-bdce-9d7028279489}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (uso).
echo Desativando log de telemetria de aplicativos (uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-0936-4a55-9d26-5f298f3180bf}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (performance).
echo Desativando log de telemetria de aplicativos (performance).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-0cc6-49da-8cd9-8903a5222aa0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (diagnóstico).
echo Desativando log de telemetria de aplicativos (diagnóstico).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-77b8-4ba8-9474-4f4a9db2f5c6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (erros).
echo Desativando log de telemetria de aplicativos (erros).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-8670-4eb6-b535-3b9d6bb222fd}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (segurança).
echo Desativando log de telemetria de aplicativos (segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-997f-49cf-b49f-ecc50184b75d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (integridade).
echo Desativando log de telemetria de aplicativos (integridade).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{75ebc33e-c8ae-4f93-9ca1-683a53e20cb6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de rede).
echo Desativando log de aplicativos (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{76ab12d5-c986-4e60-9d7c-2a092b284cdd}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de serviço).
echo Desativando log de aplicativos (eventos de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{770ca594-b467-4811-b355-28f5e5706987}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{777ba8fe-2498-4875-933a-3067de883070}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7d29d58a-931a-40ac-8743-48c733045548}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7d7b0c39-93f6-4100-bd96-4dda859652c5}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de usuário).
echo Desativando log de aplicativos (eventos de usuário).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7e58e69a-e361-4f06-b880-ad2f4b64c944}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de desempenho).
echo Desativando log de aplicativos (diagnóstico de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7e87506f-bace-4bf1-bc09-3a1f37045c71}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de plataforma).
echo Desativando log de aplicativos (eventos de plataforma).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{7eafcf79-06a7-460b-8a55-bd0a0c9248aa}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (relatório de erros).
echo Desativando log de aplicativos (relatório de erros).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8127f6d4-59f9-4abf-8952-3e3a02073d5f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{83d6e83b-900b-48a3-9835-57656b6f6474}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de inicialização).
echo Desativando log de aplicativos (eventos de inicialização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8530db6e-51c0-43d6-9d02-a8c2088526cd}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de dispositivo).
echo Desativando log de aplicativos (telemetria de dispositivo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{85a62a0d-7e17-485f-9d4f-749a287193a6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento de sessão).
echo Desativando log de aplicativos (gerenciamento de sessão).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{85be49ea-38f1-4547-a604-80060202fb27}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{85fe7609-ff4a-48e9-9d50-12918e43e1da}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de driver).
echo Desativando log de aplicativos (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{88c09888-118d-48fc-8863-e1c6d39ca4df}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de serviço).
echo Desativando log de aplicativos (telemetria de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{88cd9180-4491-4640-b571-e3bee2527943}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de serviço).
echo Desativando log de aplicativos (diagnóstico de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8939299f-2315-4c5c-9b91-abb86aa0627d}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de processo).
echo Desativando log de aplicativos (eventos de processo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{89592015-d996-4636-8f61-066b5d4dd739}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{89a2278b-c662-4aff-a06c-46ad3f220bca}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de rede).
echo Desativando log de aplicativos (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{89b1e9f0-5aff-44a6-9b44-0a07a7ce5845}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8bcdf442-3070-4118-8c94-e8843be363b3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento de perfil).
echo Desativando log de aplicativos (gerenciamento de perfil).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{8ce93926-bdae-4409-9155-2fe4799ef4d3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (AppX).
echo Desativando log de telemetria de aplicativos (AppX).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{906b8a99-63ce-58d7-86ab-10989bbd5567}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de PnP).
echo Desativando log de aplicativos (eventos de PnP).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{91f5fb12-fdea-4095-85d5-614b495cd9de}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de desempenho).
echo Desativando log de aplicativos (eventos de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9213c3e1-0d6c-52dd-78ea-f3b082111406}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de telemetria).
echo Desativando log de aplicativos (eventos de telemetria).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9363ccd9-d429-4452-9adb-2501e704b810}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de notificação).
echo Desativando log de aplicativos (eventos de notificação).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{93a19ab3-fb2c-46eb-91ef-56b0a318b983}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de dispositivo).
echo Desativando log de aplicativos (diagnóstico de dispositivo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{952773bf-c2b7-49bc-88f4-920744b82c43}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de driver).
echo Desativando log de aplicativos (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{95353826-4fbe-41d4-9c42-f521c6e86360}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento de sessão).
echo Desativando log de aplicativos (gerenciamento de sessão).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9580d7dd-0379-4658-9870-d5be7d52d6de}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de sistema).
echo Desativando log de aplicativos (telemetria de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{968f313b-097f-4e09-9cdd-bc62692d138b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de PnP).
echo Desativando log de aplicativos (eventos de PnP).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{96f4a050-7e31-453c-88be-9634f4e02139}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de erro).
echo Desativando log de aplicativos (eventos de erro).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{973143dd-f3c7-4ef5-b156-544ac38c39b6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de driver).
echo Desativando log de aplicativos (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{97ca8142-10b1-4baa-9fbb-70a7d11231c3}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de energia).
echo Desativando log de aplicativos (diagnóstico de energia).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9803daa0-81ba-483a-986c-f0e395b9f8d1}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de telemetria).
echo Desativando log de aplicativos (eventos de telemetria).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{98bf1cd3-583e-4926-95ee-a61bf3f46470}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de componentes).
echo Desativando log de aplicativos (telemetria de componentes).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{98e0765d-8c42-44a3-a57b-760d7f93225a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (AppX).
echo Desativando log de telemetria de aplicativos (AppX).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9c2a37f3-e5fd-5cae-bcd1-43dafeee1ff0}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de rede).
echo Desativando log de aplicativos (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9cc0413e-5717-4af5-82eb-6103d8707b45}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9d55b53d-449b-4824-a637-24f9d69aa02f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de telemetria).
echo Desativando log de aplicativos (eventos de telemetria).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9f973c1d-d056-4e38-84a5-7be81cdd6ab6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de processo).
echo Desativando log de aplicativos (diagnóstico de processo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{9fc66dd7-98c7-4b83-8293-46a18439b03b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de rede).
echo Desativando log de aplicativos (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a0c1853b-5c40-4b15-8766-3cf1c58f985a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos.
echo Desativando log de telemetria de aplicativos.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a615acb9-d5a4-4738-b561-1df301d207f8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a7975c8f-ac13-49f1-87da-5a984a4ab417}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de serviço).
echo Desativando log de aplicativos (diagnóstico de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a83fa99f-c356-4ded-9fd6-5a5eb8546d68}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (eventos de uso).
echo Desativando log de telemetria de aplicativos (eventos de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{a9c11050-9e93-4fa4-8fe0-7c4750a345b2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de logon).
echo Desativando log de aplicativos (eventos de logon).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aa4c798d-d91b-4b07-a013-787f5803d6fc}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de atualização).
echo Desativando log de aplicativos (eventos de atualização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aabf8b86-7936-4fa2-acb0-63127f879dbf}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de rede).
echo Desativando log de aplicativos (eventos de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aaeac398-3028-487c-9586-44eacad03637}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de desempenho).
echo Desativando log de aplicativos (eventos de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{aaf67066-0bf8-469f-ab76-275590c434ee}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{add0de40-32b0-4b58-9d5e-938b2f5c1d1f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ae4bd3be-f36f-45b6-8d21-bdd6fb832853}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de processo).
echo Desativando log de aplicativos (diagnóstico de processo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{af0a5a6d-e009-46d4-8867-42f2240f8a72}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b059b83f-d946-4b13-87ca-4292839dc2f2}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de instalação).
echo Desativando log de aplicativos (eventos de instalação).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b2fcd41f-9a40-4150-8c92-b224b7d8c8aa}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (inicialização de serviço).
echo Desativando log de aplicativos (inicialização de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4db-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de desligamento).
echo Desativando log de aplicativos (eventos de desligamento).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4de-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (inicialização de sistema).
echo Desativando log de aplicativos (inicialização de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4df-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de logon).
echo Desativando log de aplicativos (eventos de logon).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b447b4e1-7780-11e0-ada3-18a90531a85a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de armazenamento).
echo Desativando log de aplicativos (diagnóstico de armazenamento).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b6cc0d55-9ecc-49a8-b929-2b9022426f2a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de sistema).
echo Desativando log de aplicativos (telemetria de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b6d775ef-1436-4fe6-bad3-9e436319e218}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de tempo de execução).
echo Desativando log de aplicativos (eventos de tempo de execução).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b92cf7fd-dc10-4c6b-a72d-1613bf25e597}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de plataforma).
echo Desativando log de aplicativos (eventos de plataforma).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b977cf02-76f6-df84-cc1a-6a4b232322b6}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{b9da9fe6-ae5f-4f3e-b2fa-8e623c11dc75}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ba093605-3909-4345-990b-26b746adee0a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de aplicativos).
echo Desativando log de aplicativos (telemetria de aplicativos).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ba723d81-0d0c-4f1e-80c8-54740f508ddf}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de instalação).
echo Desativando log de aplicativos (eventos de instalação).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bd12f3b8-fc40-4a61-a307-b7a013a069c1}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (gerenciamento de sessão).
echo Desativando log de aplicativos (gerenciamento de sessão).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bea18b89-126f-4155-9ee4-d36038b02680}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de desempenho).
echo Desativando log de aplicativos (diagnóstico de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bf406804-6afa-46e7-8a48-6c357e1d6d61}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de telemetria).
echo Desativando log de aplicativos (eventos de telemetria).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{bff15e13-81bf-45ee-8b16-7cfead00da86}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de configuração).
echo Desativando log de aplicativos (eventos de configuração).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c2f36562-a1e4-4bc3-a6f6-01a7adb643e8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c4efc9bb-2570-4821-8923-1bad317d2d4b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c651f5f6-1c0d-492e-8ae1-b4efd7c9d503}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de aplicativo).
echo Desativando log de aplicativos (eventos de aplicativo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c6bf6832-f7bd-4151-ac21-753ce4707453}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de inicialização).
echo Desativando log de aplicativos (diagnóstico de inicialização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c76baa63-ae81-421c-b425-340b4b24157f}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de processo).
echo Desativando log de aplicativos (eventos de processo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{c9bdb4eb-9287-4c8e-8378-6896f0d1c5ef}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cab2b8a5-49b9-4eec-b1b0-fac21da05a3b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cb070027-1534-4cf3-98ea-b9751f508376}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de telemetria).
echo Desativando log de aplicativos (eventos de telemetria).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cbda4dbf-8d5d-4f69-9578-be14aa540d22}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cd7cf0d0-02cc-4872-9b65-0dba0a90efe8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de inicialização).
echo Desativando log de aplicativos (eventos de inicialização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{cf3f502e-b40d-4071-996f-00981edf938e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de falhas).
echo Desativando log de aplicativos (diagnóstico de falhas).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d0e22efc-ac66-4b25-a72d-382736b5e940}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de desempenho).
echo Desativando log de aplicativos (telemetria de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d1bc9aff-2abf-4d71-9146-ecb2a986eb85}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d2e990da-8504-4702-a5e5-367fc2f823bf}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de driver).
echo Desativando log de aplicativos (diagnóstico de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d39b6336-cfcb-483b-8c76-7c3e7d02bcb8}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d3f29eda-805d-428a-9902-b259b937f84b}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d710d46c-235d-4798-ac20-9f83e1dcd557}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de serviço).
echo Desativando log de aplicativos (eventos de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{d8965fcf-7397-4e0e-b750-21a4580bd880}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de conectividade).
echo Desativando log de aplicativos (eventos de conectividade).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{dab3b18c-3c0f-43e8-80b1-e44bc0dad901}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de sistema).
echo Desativando log de aplicativos (telemetria de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{db00dfb6-29f9-4a9c-9b3b-1f4f9e7d9770}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de desempenho).
echo Desativando log de aplicativos (diagnóstico de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{dbe9b383-7cf3-4331-91cc-a3cb16a3b538}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de logon).
echo Desativando log de aplicativos (eventos de logon).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{dcbe5aaa-16e2-457c-9337-366950045f0a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{de095dbe-8667-4168-94c2-48ca61665aca}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de driver).
echo Desativando log de aplicativos (telemetria de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{de513a55-c345-438b-9a74-e18cac5c5cc5}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de disco).
echo Desativando log de aplicativos (diagnóstico de disco).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{de7b24ea-73c8-4a09-985d-5bdadcfa9017}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (AppX).
echo Desativando log de telemetria de aplicativos (AppX).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e0c6f6de-258a-50e0-ac1a-103482d118bc}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de plataforma).
echo Desativando log de aplicativos (eventos de plataforma).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e1dd7e52-621d-44e3-a1ad-0370c2b25946}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de desempenho).
echo Desativando log de aplicativos (diagnóstico de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e4d53f84-7de3-11d8-9435-505054503030}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de serviço).
echo Desativando log de aplicativos (eventos de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e4f68870-5ae8-4e5b-9ce7-ca9ed75b0245}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e53df8ba-367a-4406-98d5-709ffb169681}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e5c16d49-2464-4382-bb20-97a4b5465db9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de plataforma).
echo Desativando log de aplicativos (telemetria de plataforma).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e6307a09-292c-497e-aad6-498f68e2b619}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e6835967-e0d2-41fb-bcec-58387404e25a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de driver).
echo Desativando log de aplicativos (eventos de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{e7558269-3fa5-46ed-9f4d-3c6e282dde55}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ea8cd8a5-78ff-4418-b292-aadc6a7181df}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ec23f986-ae2d-4269-b52f-4e20765c1a94}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de serviço).
echo Desativando log de aplicativos (eventos de serviço).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ed8b9bd3-f66e-4ff2-b86b-75c7925f72a9}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de inicialização).
echo Desativando log de aplicativos (eventos de inicialização).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{eef54e71-0661-422d-9a98-82fd4940b820}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de desempenho).
echo Desativando log de aplicativos (telemetria de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f0be35f8-237b-4814-86b5-ade51192e503}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de armazenamento).
echo Desativando log de aplicativos (eventos de armazenamento).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f0db7ef8-b6f3-4005-9937-feb77b9e1b43}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de sistema).
echo Desativando log de aplicativos (telemetria de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f1201b5a-e170-42b6-8d20-b57ac57e6416}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de instalação).
echo Desativando log de aplicativos (eventos de instalação).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f1394de0-32c7-4a76-a6de-b245e48f4615}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de processo).
echo Desativando log de aplicativos (diagnóstico de processo).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f1ef270a-0d32-4352-ba52-dbab41e1d859}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de segurança).
echo Desativando log de aplicativos (eventos de segurança).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f2311b48-32be-4902-a22a-7240371dbb2c}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de desempenho).
echo Desativando log de aplicativos (telemetria de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f3f53c76-b06d-4f15-b412-61164a0d2b73}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (AppX).
echo Desativando log de telemetria de aplicativos (AppX).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f43c3c35-22e2-53eb-f169-07594054779e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sessão).
echo Desativando log de aplicativos (eventos de sessão).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f4aed7c7-a898-4627-b053-44a7caa12fcd}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de driver).
echo Desativando log de aplicativos (telemetria de driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f5dbaa02-15d6-4644-a784-7032d508bf64}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f82fb576-e941-4956-a2c7-a0cf83f6450a}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (Shell).
echo Desativando log de telemetria de aplicativos (Shell).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f8ad09ba-419c-5134-1750-270f4d0fb889}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de rede).
echo Desativando log de aplicativos (diagnóstico de rede).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{f9fe3908-44b8-48d9-9a32-5a763ff5ed79}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de logon).
echo Desativando log de aplicativos (eventos de logon).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fa773482-f6ed-4895-8a7d-4f5850678e59}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de uso).
echo Desativando log de aplicativos (telemetria de uso).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fae10392-f0af-4ac0-b8ff-9f4d920c3cdf}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de telemetria de aplicativos (Driver).
echo Desativando log de telemetria de aplicativos (Driver).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fae96d09-ade1-5223-0098-af7b67348531}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de plataforma).
echo Desativando log de aplicativos (eventos de plataforma).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fb829150-cd7d-44c3-af5b-711a3c31cedc}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (diagnóstico de conectividade).
echo Desativando log de aplicativos (diagnóstico de conectividade).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fbcfac3f-8459-419f-8e48-1f0b49cdb85e}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (telemetria de desempenho).
echo Desativando log de aplicativos (telemetria de desempenho).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desativando log de aplicativos (eventos de sistema).
echo Desativando log de aplicativos (eventos de sistema).
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\Autologger\EventLog-Application\{ff79a477-c45f-4a52-8ae0-2b324346d4e4}" /v "Enabled" /t REG_DWORD /d "0" /f

:: Desabilita a inicialização de I/O em buffer.
echo Desabilita I/O em buffer.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "DisableBufferedIoInit" /t REG_DWORD /d "0" /f

:: Aumenta os locais de pilha IRP grandes.
echo Aumenta pilhas IRP grandes.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "LargeIrpStackLocations" /t REG_DWORD /d "20" /f

:: Define os locais de pilha IRP médios.
echo Define pilhas IRP médias.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "MediumIrpStackLocations" /t REG_DWORD /d "8" /f

:: Habilita verificação de acesso à sessão zero para I/O.
echo Habilita verificação de sessão zero I/O.
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\I/O System" /v "IoEnableSessionZeroAccessCheck" /t REG_DWORD /d "1" /f

:: Remove o limite de largura de banda de I/O.
echo Remove limite de banda I/O.
reg add "HKLM\System\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f

:: Permite I/O mapeada para todos os processos.
echo Permite I/O mapeada para todos.
reg add "HKLM\System\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "NoCapAllowMappedIOForAllProcesses" /t REG_DWORD /d "1" /f

:: Define o limite de "Commit" de memória para o máximo.
echo Maximiza limite de memória.
reg add "HKLM\System\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitLimit" /t REG_DWORD /d "4294967295" /f

:: Define o alvo de "Commit" de memória para o máximo.
echo Maximiza alvo de memória.
reg add "HKLM\System\ResourcePolicyStore\ResourceSets\Policies\Memory\NoCap" /v "CommitTarget" /t REG_DWORD /d "4294967295" /f

:: Altera a separação de prioridade Win32.
echo Altera prioridade Win32.
reg add "HKLM\System\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d "40" /f

:: Remove o limite de uso de CPU para "HardCap0".
echo Remove limite CPU "HardCap0".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "CapPercentage" /t REG_DWORD /d "0" /f

:: Define o tipo de agendamento de CPU para "HardCap0".
echo Define agendamento CPU "HardCap0".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\HardCap0" /v "SchedulingType" /t REG_DWORD /d "0" /f

:: Remove o limite de uso de CPU para "Paused".
echo Remove limite CPU "Paused".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "CapPercentage" /t REG_DWORD /d "0" /f

:: Define o tipo de agendamento de CPU para "Paused".
echo Define agendamento CPU "Paused".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\Paused" /v "SchedulingType" /t REG_DWORD /d "0" /f

:: Remove o limite de uso de CPU para "SoftCapFull".
echo Remove limite CPU "SoftCapFull".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "CapPercentage" /t REG_DWORD /d "0" /f

:: Define o tipo de agendamento de CPU para "SoftCapFull".
echo Define agendamento CPU "SoftCapFull".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapFull" /v "SchedulingType" /t REG_DWORD /d "0" /f

:: Remove o limite de uso de CPU para "SoftCapLow".
echo Remove limite CPU "SoftCapLow".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "CapPercentage" /t REG_DWORD /d "0" /f

:: Define o tipo de agendamento de CPU para "SoftCapLow".
echo Define agendamento CPU "SoftCapLow".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\CPU\SoftCapLow" /v "SchedulingType" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "BackgroundDefault".
echo Prioridade normal para "BackgroundDefault".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\BackgroundDefault" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "Frozen".
echo Prioridade normal para "Frozen".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Frozen" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "FrozenDNCS".
echo Prioridade normal para "FrozenDNCS".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNCS" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "FrozenDNK".
echo Prioridade normal para "FrozenDNK".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "FrozenPPLE".
echo Prioridade normal para "FrozenPPLE".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\FrozenPPLE" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "Paused".
echo Prioridade normal para "Paused".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Paused" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "PausedDNK".
echo Prioridade normal para "PausedDNK".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PausedDNK" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "Pausing".
echo Prioridade normal para "Pausing".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\Pausing" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "PrelaunchForeground".
echo Prioridade normal para "PrelaunchForeground".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\PrelaunchForeground" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Define prioridade normal para "ThrottleGPUInterference".
echo Prioridade normal para "ThrottleGPUInterference".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Flags\ThrottleGPUInterference" /v "IsLowPriority" /t REG_DWORD /d "0" /f

:: Ajusta prioridade base para "Critical".
echo Ajusta prioridade base "Critical".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "Critical".
echo Ajusta prioridade alvo "Critical".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Critical" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "CriticalNoUi".
echo Ajusta prioridade base "CriticalNoUi".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "CriticalNoUi".
echo Ajusta prioridade alvo "CriticalNoUi".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\CriticalNoUi" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "EmptyHostPPLE".
echo Ajusta prioridade base "EmptyHostPPLE".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "EmptyHostPPLE".
echo Ajusta prioridade alvo "EmptyHostPPLE".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\EmptyHostPPLE" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "High".
echo Ajusta prioridade base "High".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "High".
echo Ajusta prioridade alvo "High".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\High" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "Low".
echo Ajusta prioridade base "Low".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "Low".
echo Ajusta prioridade alvo "Low".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Low" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "Lowest".
echo Ajusta prioridade base "Lowest".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "Lowest".
echo Ajusta prioridade alvo "Lowest".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Lowest" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "Medium".
echo Ajusta prioridade base "Medium".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "Medium".
echo Ajusta prioridade alvo "Medium".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\Medium" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "MediumHigh".
echo Ajusta prioridade base "MediumHigh".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "MediumHigh".
echo Ajusta prioridade alvo "MediumHigh".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\MediumHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "StartHost".
echo Ajusta prioridade base "StartHost".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "StartHost".
echo Ajusta prioridade alvo "StartHost".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\StartHost" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "VeryHigh".
echo Ajusta prioridade base "VeryHigh".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "VeryHigh".
echo Ajusta prioridade alvo "VeryHigh".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryHigh" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Ajusta prioridade base para "VeryLow".
echo Ajusta prioridade base "VeryLow".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "BasePriority" /t REG_DWORD /d "82" /f

:: Ajusta prioridade sobre alvo para "VeryLow".
echo Ajusta prioridade alvo "VeryLow".
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\Importance\VeryLow" /v "OverTargetPriority" /t REG_DWORD /d "50" /f

:: Remove o limite de largura de banda de I/O.
echo Remove limite de banda I/O.
reg add "HKLM\SYSTEM\ResourcePolicyStore\ResourceSets\Policies\IO\NoCap" /v "IOBandwidth" /t REG_DWORD /d "0" /f
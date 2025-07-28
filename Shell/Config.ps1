Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Disabling telemetry via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" "AllowTelemetry" 0

Write-Output "Adding telemetry domains to hosts file"
$hosts_file = "$env:systemroot\System32\drivers\etc\hosts"
$domains = @(
    "184-86-53-99.deploy.static.akamaitechnologies.com"
    "a-0001.a-msedge.net"
    "a-0002.a-msedge.net"
    "a-0003.a-msedge.net"
    "a-0004.a-msedge.net"
    "a-0005.a-msedge.net"
    "a-0006.a-msedge.net"
    "a-0007.a-msedge.net"
    "a-0008.a-msedge.net"
    "a-0009.a-msedge.net"
    "a1621.g.akamai.net"
    "a1856.g2.akamai.net"
    "a1961.g.akamai.net"
    "a978.i6g1.akamai.net"
    "a.ads1.msn.com"
    "a.ads2.msads.net"
    "a.ads2.msn.com"
    "ac3.msn.com"
    "ad.doubleclick.net"
    "adnexus.net"
    "adnxs.com"
    "ads1.msads.net"
    "ads1.msn.com"
    "ads.msn.com"
    "aidps.atdmt.com"
    "aka-cdn-ns.adtech.de"
    "a-msedge.net"
    "any.edge.bing.com"
    "a.rad.msn.com"
    "az361816.vo.msecnd.net"
    "az512334.vo.msecnd.net"
    "b.ads1.msn.com"
    "b.ads2.msads.net"
    "bingads.microsoft.com"
    "b.rad.msn.com"
    "bs.serving-sys.com"
    "c.atdmt.com"
    "cdn.atdmt.com"
    "cds26.ams9.msecn.net"
    "choice.microsoft.com"
    "choice.microsoft.com.nsatc.net"
    "compatexchange.cloudapp.net"
    "corpext.msitadfs.glbdns2.microsoft.com"
    "corp.sts.microsoft.com"
    "cs1.wpc.v0cdn.net"
    "db3aqu.atdmt.com"
    "df.telemetry.microsoft.com"
    "diagnostics.support.microsoft.com"
    "e2835.dspb.akamaiedge.net"
    "e7341.g.akamaiedge.net"
    "e7502.ce.akamaiedge.net"
    "e8218.ce.akamaiedge.net"
    "ec.atdmt.com"
    "fe2.update.microsoft.com.akadns.net"
    "feedback.microsoft-hohm.com"
    "feedback.search.microsoft.com"
    "feedback.windows.com"
    "flex.msn.com"
    "g.msn.com"
    "h1.msn.com"
    "h2.msn.com"
    "hostedocsp.globalsign.com"
    "i1.services.social.microsoft.com"
    "i1.services.social.microsoft.com.nsatc.net"
    "lb1.www.ms.akadns.net"
    "live.rads.msn.com"
    "m.adnxs.com"
    "msedge.net"
    "msnbot-65-55-108-23.search.msn.com"
    "msntest.serving-sys.com"
    "oca.telemetry.microsoft.com"
    "oca.telemetry.microsoft.com.nsatc.net"
    "onesettings-db5.metron.live.nsatc.net"
    "pre.footprintpredict.com"
    "preview.msn.com"
    "rad.live.com"
    "rad.msn.com"
    "redir.metaservices.microsoft.com"
    "reports.wes.df.telemetry.microsoft.com"
    "schemas.microsoft.akadns.net"
    "secure.adnxs.com"
    "secure.flashtalking.com"
    "services.wes.df.telemetry.microsoft.com"
    "settings-sandbox.data.microsoft.com"
    "sls.update.microsoft.com.akadns.net"
    "sqm.df.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com"
    "sqm.telemetry.microsoft.com.nsatc.net"
    "ssw.live.com"
    "static.2mdn.net"
    "statsfe1.ws.microsoft.com"
    "statsfe2.update.microsoft.com.akadns.net"
    "statsfe2.ws.microsoft.com"
    "survey.watson.microsoft.com"
    "telecommand.telemetry.microsoft.com"
    "telecommand.telemetry.microsoft.com.nsatc.net"
    "telemetry.appex.bing.net"
    "telemetry.microsoft.com"
    "telemetry.urs.microsoft.com"
    "vortex-bn2.metron.live.com.nsatc.net"
    "vortex-cy2.metron.live.com.nsatc.net"
    "vortex.data.microsoft.com"
    "vortex-sandbox.data.microsoft.com"
    "vortex-win.data.microsoft.com"
    "cy2.vortex.data.microsoft.com.akadns.net"
    "watson.live.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "win10.ipv6.microsoft.com"
    "www.bingads.microsoft.com"
    "www.go.microsoft.akadns.net"
    "client.wns.windows.com"
    "wdcpalt.microsoft.com"
    "settings-ssl.xboxlive.com"
    "settings-ssl.xboxlive.com-c.edgekey.net"
    "settings-ssl.xboxlive.com-c.edgekey.net.globalredir.akadns.net"
    "e87.dspb.akamaidege.net"
    "insiderservice.microsoft.com"
    "insiderservice.trafficmanager.net"
    "e3843.g.akamaiedge.net"
    "flightingserviceweurope.cloudapp.net"
    "static.ads-twitter.com"                    
    "www-google-analytics.l.google.com"
    "p.static.ads-twitter.com"               
    "hubspot.net.edge.net"
    "e9483.a.akamaiedge.net"
    "stats.g.doubleclick.net"
    "stats.l.doubleclick.net"
    "adservice.google.de"
    "adservice.google.com"
    "googleads.g.doubleclick.net"
    "pagead46.l.doubleclick.net"
    "hubspot.net.edgekey.net"
    "insiderppe.cloudapp.net"                   
    "livetileedge.dsx.mp.microsoft.com"
    "fe2.update.microsoft.com.akadns.net"
    "s0.2mdn.net"
    "statsfe2.update.microsoft.com.akadns.net"
    "survey.watson.microsoft.com"
    "view.atdmt.com"
    "watson.microsoft.com"
    "watson.ppe.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com"
    "watson.telemetry.microsoft.com.nsatc.net"
    "wes.df.telemetry.microsoft.com"
    "m.hotmail.com"
    "apps.skype.com"
    "c.msn.com"
    "pricelist.skype.com"
    "s.gateway.messenger.live.com"
    "ui.skype.com"
)

Write-Output "" | Out-File -Encoding ASCII -Append $hosts_file
foreach ($domain in $domains) {
    if (-Not (Select-String -Path $hosts_file -Pattern $domain)) {
        Write-Output "0.0.0.0 $domain" | Out-File -Encoding ASCII -Append $hosts_file
    }
}

Write-Output "Adding telemetry ips to firewall"
$ips = @(

    "134.170.30.202"
    "137.116.81.24"
    "157.56.106.189"
    "184.86.53.99"
    "2.22.61.43"
    "2.22.61.66"
    "204.79.197.200"
    "23.218.212.69"
    "65.39.117.230"
    "65.52.108.33"   
    "65.55.108.23"
    "64.4.54.254"
    "8.36.80.197"
    "8.36.80.224"
    "8.36.80.252"
    "8.36.113.118"
    "8.36.113.141"
    "8.36.80.230"
    "8.36.80.231"
    "8.36.113.126"
    "8.36.80.195"
    "8.36.80.217"
    "8.36.80.237"
    "8.36.80.246"
    "8.36.113.116"
    "8.36.113.139"
    "8.36.80.244"
    "216.228.121.209"
)
Remove-NetFirewallRule -DisplayName "Block Telemetry IPs" -ErrorAction SilentlyContinue
New-NetFirewallRule -DisplayName "Block Telemetry IPs" -Direction Outbound `
    -Action Block -RemoteAddress ([string[]]$ips)
$tasks = @(
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Application Experience\StartupAppTask"
    "\Microsoft\Windows\Application Experience\PcaPatchDbTask"
)

foreach ($task in $tasks) {
   Disable-ScheduledTask -TaskName $task
}

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
	Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
	Exit
}

Write-Host "Disabling Telemetry..."
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

Write-Host "Disabling Wi-Fi Sense..."
If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
	New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
}
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0

Write-Host "Disabling SmartScreen Filter..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name "SmartScreenEnabled" -Type String -Value "Off"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 0

Write-Host "Disabling Bing Search in Start Menu..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Type DWord -Value 0

Write-Host "Disabling Location Tracking..."
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

Write-Host "Disabling Feedback..."
If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
	New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0


Write-Host "Disabling Advertising ID..."
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0


Write-Host "Disabling Cortana..."
If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
	New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
	New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0


Write-Host "Restricting Windows Update P2P only to local network..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
	New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
}
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3


Write-Host "Removing AutoLogger file and restricting directory..."
$autoLoggerDir = "$env:PROGRAMDATA\Microsoft\Diagnosis\ETLLogs\AutoLogger"
If (Test-Path "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl") {
	Remove-Item "$autoLoggerDir\AutoLogger-Diagtrack-Listener.etl"
}
icacls $autoLoggerDir /deny SYSTEM:`(OI`)`(CI`)F | Out-Null

Write-Host "Stopping and disabling Diagnostics Tracking Service..."
Stop-Service "DiagTrack"
Set-Service "DiagTrack" -StartupType Disabled

Write-Host "Disabling Windows Update automatic restart..."
Set-ItemProperty -Path "HKLM:\Software\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value 1

Write-Host "Stopping and disabling Home Groups services..."
Stop-Service "HomeGroupListener"
Set-Service "HomeGroupListener" -StartupType Disabled
Stop-Service "HomeGroupProvider"
Set-Service "HomeGroupProvider" -StartupType Disabled

Write-Host "Disabling Remote Assistance..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Type DWord -Value 1
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Type DWord -Value 1

Write-Host "Hiding Search Box / Button..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

Write-Host "Showing known file extensions..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Type DWord -Value 0

Write-Host "Changing default Explorer view to `"Computer`"..."
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

Write-Host "Disabling OneDrive..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
	New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1

Write-Host "Uninstalling default Microsoft applications..."
Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
Get-AppxPackage "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Wallet" | Remove-AppxPackage
Get-AppxPackage "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage "Microsoft.MixedReality.Portal" | Remove-AppxPackage
Get-AppxPackage "Microsoft.XboxIdentityProvider" | Remove-AppPackage
Get-AppxPackage "5A894077.McAfeeSecurity" | Remove-AppPackage
Get-AppxPackage "Disney.37853FC22B2CE" | Remove-AppPackage
Get-AppxPackage "Microsoft.GamingApp" | Remove-AppPackage
Get-AppxPackage "Facebook.InstagramBeta" | Remove-AppPackage
Get-AppxPackage "AdobeSystemsIncorporated.AdobeCreativeCloudExpress" | Remove-AppPackage
Get-AppxPackage "AmazonVideo.PrimeVideo" | Remove-AppPackage
Get-AppxPackage "BytedancePte.Ltd.TikTok" | Remove-AppPackage

Write-Host "Uninstalling Work Folders Client..."
dism /online /Disable-Feature /FeatureName:WorkFolders-Client /Quiet /NoRestart


$services = @(
    "diagnosticshub.standardcollector.service" 
    "DiagTrack"                                
    "dmwappushservice"                         
    "lfsvc"                                   
    "MapsBroker"                               
    "NetTcpPortSharing"                       
    "RemoteAccess"                            
  
    "SharedAccess"                            
    "TrkWks"                                   
    
    "WMPNetworkSvc"                            
   
    
    "XblAuthManager"                          
    "XblGameSave"                              
    "XboxNetApiSvc"                           
    "ndu"                                     

)

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Disable automatic download and installation of Windows updates"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3

Write-Output "Disable seeding of updates to other computers via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value


Write-Output "Disable 'Updates are available' message"

takeown /F "$env:WinDIR\System32\MusNotification.exe"
icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Uninstalling default apps"
$apps = @(
    
    "Microsoft.3DBuilder"
    "Microsoft.Advertising.Xaml"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.FreshPaint"
    "Microsoft.GamingServices"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MixedReality.Portal"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MinecraftUWP"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.Windows.CloudExperienceHost"
    "Microsoft.Windows.ContentDeliveryManager"
    "Microsoft.Windows.PeopleExperienceHost"
    "Microsoft.XboxGameCallableUI"
    "Microsoft.GamingApp"
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.WindowsReadingList"
    "Microsoft.MixedReality.Portal"
    "Microsoft.XboxGamingOverlay"
    "Microsoft.YourPhone"
    "2FE3CB00.PicsArt-PhotoStudio"
    "46928bounde.EclipseManager"
    "4DF9E0F8.Netflix"
    "613EBCEA.PolarrPhotoEditorAcademicEdition"
    "6Wunderkinder.Wunderlist"
    "7EE7776C.LinkedInforWindows"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.MarchofEmpires"
    "ActiproSoftwareLLC.562882FEEB491"
    "CAF9E577.Plex"
    "ClearChannelRadioDigital.iHeartRadio"
    "D52A8D61.FarmVille2CountryEscape"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "DolbyLaboratories.DolbyAccess"
    "DolbyLaboratories.DolbyAccess"
    "Drawboard.DrawboardPDF"
    "Facebook.Facebook"
    "Fitbit.FitbitCoach"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "KeeperSecurityInc.Keeper"
    "NORDCURRENT.COOKINGFEVER"
    "PandoraMediaInc.29680B314EFC2"
    "Playtika.CaesarsSlotsFreeCasino"
    "ShazamEntertainmentLtd.Shazam"
    "SlingTVLLC.SlingTV"
    "SpotifyAB.SpotifyMusic"
    "TheNewYorkTimes.NYTCrossword"
    "ThumbmunkeysLtd.PhototasticCollage"
    "TuneIn.TuneInRadio"
    "WinZipComputing.WinZipUniversal"
    "XINGAG.XING"
    "flaregamesGmbH.RoyalRevolt2"
    "king.com.*"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "5A894077.McAfeeSecurity"
    "Disney.37853FC22B2CE"
    "Facebook.InstagramBeta"
    "AdobeSystemsIncorporated.AdobeCreativeCloudExpress"
    "AmazonVideo.PrimeVideo"
    "BytedancePte.Ltd.TikTok"
    "Microsoft.Advertising.Xaml"
)

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    Get-AppXProvisionedPackage -Online |
        Where-Object DisplayName -EQ $app |
        Remove-AppxProvisionedPackage -Online
}

$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"

If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

Write-Output "Removing additional OneDrive leftovers"
foreach ($item in (Get-ChildItem "$env:WinDir\WinSxS\*onedrive*")) {
    Takeown-Folder $item.FullName
    Remove-Item -Recurse -Force $item.FullName
}

net accounts /maxpwage:0

Stop-Process -name explorer

Import-StartLayout -LayoutPath $layoutFile -MountPath $env:SystemDrive\

Remove-Item $layoutFile

reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "DelayedAutoStart" /t REG_DWORD /d "1"
reg delete "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\dmwappushservice" /v "Start" /t REG_DWORD /d "2"
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Settings\FindMyDevice" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack" /v "ShowedToastAtLevel" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "1" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MaxTelemetryAllowed" /t REG_DWORD /d "1" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t "REG_DWORD" /d "0" /f
reg add "HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t "REG_DWORD" /d "0" /f

$services = @(
    "diagnosticshub.standardcollector.service" 
    "DiagTrack"                               
    "dmwappushservice"                        
    "lfsvc"                                   
    "MapsBroker"                              
    "NetTcpPortSharing"                        
    "RemoteAccess"                           
    "RemoteRegistry"                          
    "SharedAccess"                             
    "TrkWks"                                   
    "WbioSrvc"                                
 
    "WMPNetworkSvc"                        
  
    "XblAuthManager"                         
    "XblGameSave"                             
    "XboxNetApiSvc"                           
    "ndu"                                      

)

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

$tasks = @(
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"
)

foreach ($task in $tasks) {
    $parts = $task.split('\')
    $name = $parts[-1]
    $path = $parts[0..($parts.length-2)] -join '\'

    Write-Output "Trying to disable scheduled task $name"
    Disable-ScheduledTask -TaskName "$name" -TaskPath "$path"
}

Write-Output "Disabling Windows Defender via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableAntiSpyware" 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender" "DisableRoutinelyTakingAction" 1
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows Defender\Real-Time Protection" "DisableRealtimeMonitoring" 1

Write-Output "Disabling Windows Defender Services"
Takeown-Registry("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend")
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinDefend" "AutorunsDisabled" 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdNisSvc" "AutorunsDisabled" 3
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "Start" 4
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Sense" "AutorunsDisabled" 3

Write-Output "Removing Windows Defender context menu item"
Set-Item "HKLM:\SOFTWARE\Classes\CLSID\{09A47860-11B0-4DA5-AFA5-26D86198A780}\InprocServer32" ""

Write-Output "Removing Windows Defender GUI / tray from autorun"
Remove-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" "WindowsDefender" -ea 0

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Force removing system apps"
$needles = @(
    "BioEnrollment"
    "ContactSupport"
    "Feedback"
    "Flash"
    "Gaming"
    "OneDrive"
    
)

foreach ($needle in $needles) {
    Write-Output "Trying to remove all packages containing $needle"

    $pkgs = (Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages" |
        Where-Object Name -Like "*$needle*")

    foreach ($pkg in $pkgs) {
        $pkgname = $pkg.Name.split('\')[-1]

        Takeown-Registry($pkg.Name)
        Takeown-Registry($pkg.Name + "\Owners")

        Set-ItemProperty -Path ("HKLM:" + $pkg.Name.Substring(18)) -Name Visibility -Value 1
        New-ItemProperty -Path ("HKLM:" + $pkg.Name.Substring(18)) -Name DefVis -PropertyType DWord -Value 2
        Remove-Item      -Path ("HKLM:" + $pkg.Name.Substring(18) + "\Owners")

        dism.exe /Online /Remove-Package /PackageName:$pkgname /NoRestart
    }
}

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Defuse Windows search settings"
Set-WindowsSearchSetting -EnableWebResultsSetting $false

Write-Output "Set general privacy options"
Set-ItemProperty -Path "HKCU:\Control Panel\International\User Profile" "HttpAcceptLanguageOptOut" 1
New-FolderForced -Path "HKCU:\Printers\Defaults"
Set-ItemProperty -Path "HKCU:\Printers\Defaults" "NetID" "{00000000-0000-0000-0000-000000000000}"
New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Input\TIPC" "Enabled" 0
New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "Enabled" 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" "EnableWebContentEvaluation" 0

Write-Output "Disable synchronisation of settings"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" 0x3c
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "DeviceMetadataUploaded" 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync" "PriorLogons" 1
$groups = @(
    "Accessibility"
    "AppSync"
    "BrowserSettings"
    "Credentials"
    "DesktopTheme"
    "Language"
    "PackageState"
    "Personalization"
    "StartLayout"
    "Windows"
)
foreach ($group in $groups) {
    New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group"
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\SettingSync\Groups\$group" "Enabled" 0
}

Write-Output "Set privacy policy accepted state to 0"

New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" "AcceptedPrivacyPolicy" 0

Write-Output "Do not scan contact informations"

New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" "HarvestContacts" 0

Write-Output "Inking and typing settings"

New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitInkCollection" 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" "RestrictImplicitTextCollection" 1

Write-Output "Microsoft Edge settings"
New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Main" "DoNotTrack" 1
New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\User\Default\SearchScopes" "ShowSearchSuggestionsGlobal" 0
New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\FlipAhead" "FPEnabled" 0
New-FolderForced -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" "EnabledV9" 0

Write-Output "Disable background access of default apps"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications")) {
    Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications\" + $key.PSChildName) "Disabled" 1
}

Write-Output "Denying device access"

Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Type" "LooselyCoupled"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "Value" "Deny"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" "InitialAppValue" "Unspecified"
foreach ($key in (Get-ChildItem "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global")) {
    if ($key.PSChildName -EQ "LooselyCoupled") {
        continue
    }
    Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Type" "InterfaceClass"
    Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "Value" "Deny"
    Set-ItemProperty -Path ("HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\" + $key.PSChildName) "InitialAppValue" "Unspecified"
}

Write-Output "Disable location sensor"
New-FolderForced -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" "SensorPermissionState" 0

Write-Output "Disable submission of Windows Defender findings (w/ elevated privileges)"
Takeown-Registry("HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Spynet")
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SpyNetReporting" 0       
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Spynet" "SubmitSamplesConsent" 0

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Elevating priviledges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Apply MarkC's mouse acceleration fix"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" "MouseSensitivity" "10"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" "MouseSpeed" "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" "MouseThreshold1" "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" "MouseThreshold2" "0"
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" "SmoothMouseXCurve" ([byte[]](0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0xCC, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
0x80, 0x99, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x66, 0x26, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x33, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00))
Set-ItemProperty -Path "HKCU:\Control Panel\Mouse" "SmoothMouseYCurve" ([byte[]](0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00))

Write-Output "Disable mouse pointer hiding"
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" "UserPreferencesMask" ([byte[]](0x9e,
0x1e, 0x06, 0x80, 0x12, 0x00, 0x00, 0x00))

Write-Output "Disable Game DVR and Game Bar"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowgameDVR" 0

Write-Output "Disable easy access keyboard stuff"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\StickyKeys" "Flags" "506"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\Keyboard Response" "Flags" "122"
Set-ItemProperty -Path "HKCU:\Control Panel\Accessibility\ToggleKeys" "Flags" "58"

Write-Output "Disable Edge desktop shortcut on new profiles"
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer" -Name DisableEdgeDesktopShortcutCreation -PropertyType DWORD -Value 1

Write-Output "Restoring old volume slider"
New-FolderForced -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC"
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\MTCUVC" "EnableMtcUvc" 0

Write-Output "Setting folder view options"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "Hidden" 1
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideFileExt" 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "HideDrivesWithNoMedia" 0
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "ShowSyncProviderNotifications" 0

Write-Output "Disable Aero-Shake Minimize feature"
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "DisallowShaking" 1

Write-Output "Setting default explorer view to This PC"
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "LaunchTo" 1

Write-Output "Disabling Trending Searches"
New-FolderForced -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer"
Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" "DisableSearchBoxSuggestions" 1

Write-Output "Removing user folders under This PC"

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{B4BFCC3A-DB2C-424C-B029-7FE99A87C641}"

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A8CDFF1C-4878-43be-B5FD-F8091C1C60D0}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{d3162b92-9365-467a-956b-92703aca08af}"

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{374DE290-123F-4565-9164-39C4925E467B}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{088e3905-0323-4b02-9826-5d99428e115f}"

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{1CF1260C-4DD0-4ebb-811F-33C572699FDE}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3dfdf296-dbec-4fb4-81d1-6a3438bcf4de}"

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{3ADD1653-EB32-4cb0-BBD7-DFA0ABB5ACCA}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{24ad3ad4-a569-4530-98e1-ab02f9417aa8}"

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{A0953C92-50DC-43bf-BE83-3742FED03C9C}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{f86fa3ab-70d2-4fc7-9c99-fcbf05467f3a}"

Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"
Remove-Item -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}"

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Disable automatic download and installation of Windows updates"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoUpdate" 1
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "AUOptions" 2
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallDay" 0
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU" "ScheduledInstallTime" 3

Write-Output "Disable seeding of updates to other computers via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" "DODownloadMode" 0

$objSID = New-Object System.Security.Principal.SecurityIdentifier "S-1-1-0"
$EveryOne = $objSID.Translate( [System.Security.Principal.NTAccount]).Value

Write-Output "Disable 'Updates are available' message"

takeown /F "$env:WinDIR\System32\MusNotification.exe"
icacls "$env:WinDIR\System32\MusNotification.exe" /deny "$($EveryOne):(X)"
takeown /F "$env:WinDIR\System32\MusNotificationUx.exe"
icacls "$env:WinDIR\System32\MusNotificationUx.exe" /deny "$($EveryOne):(X)"

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1

Write-Output "Elevating privileges for this process"
do {} until (Elevate-Privileges SeTakeOwnershipPrivilege)

Write-Output "Uninstalling default apps"
$apps = @(

    "Microsoft.549981C3F5F10" 
    "Microsoft.3DBuilder"
    "Microsoft.Appconnector"
    "Microsoft.BingFinance"
    "Microsoft.BingNews"
    "Microsoft.BingSports"
    "Microsoft.BingTranslator"
    "Microsoft.BingWeather"
    "Microsoft.GamingServices"
    "Microsoft.MicrosoftOfficeHub"
    "Microsoft.MicrosoftPowerBIForWindows"
    "Microsoft.MicrosoftSolitaireCollection"
    "Microsoft.MinecraftUWP"
    "Microsoft.NetworkSpeedTest"
    "Microsoft.Office.OneNote"
    "Microsoft.People"
    "Microsoft.Print3D"
    "Microsoft.SkypeApp"
    "Microsoft.Wallet"
    "Microsoft.WindowsAlarms"
    "Microsoft.WindowsCamera"
    "microsoft.windowscommunicationsapps"
    "Microsoft.WindowsMaps"
    "Microsoft.WindowsPhone"
    "Microsoft.WindowsSoundRecorder"
    "Microsoft.Xbox.TCUI"
    "Microsoft.XboxApp"
    "Microsoft.XboxGameOverlay"
    "Microsoft.XboxSpeechToTextOverlay"
    "Microsoft.YourPhone"
    "Microsoft.ZuneMusic"
    "Microsoft.ZuneVideo"
    "Microsoft.CommsPhone"
    "Microsoft.ConnectivityStore"
    "Microsoft.GetHelp"
    "Microsoft.Getstarted"
    "Microsoft.Messaging"
    "Microsoft.Office.Sway"
    "Microsoft.OneConnect"
    "Microsoft.WindowsFeedbackHub"
    "Microsoft.Microsoft3DViewer"
    "Microsoft.BingFoodAndDrink"
    "Microsoft.BingHealthAndFitness"
    "Microsoft.BingTravel"
    "Microsoft.WindowsReadingList"
    "Microsoft.MixedReality.Portal"
    "Microsoft.ScreenSketch"
    "Microsoft.XboxGamingOverlay"
    "2FE3CB00.PicsArt-PhotoStudio"
    "46928bounde.EclipseManager"
    "4DF9E0F8.Netflix"
    "613EBCEA.PolarrPhotoEditorAcademicEdition"
    "6Wunderkinder.Wunderlist"
    "7EE7776C.LinkedInforWindows"
    "89006A2E.AutodeskSketchBook"
    "9E2F88E3.Twitter"
    "A278AB0D.DisneyMagicKingdoms"
    "A278AB0D.MarchofEmpires"
    "ActiproSoftwareLLC.562882FEEB491" 
    "CAF9E577.Plex"  
    "ClearChannelRadioDigital.iHeartRadio"
    "D52A8D61.FarmVille2CountryEscape"
    "D5EA27B7.Duolingo-LearnLanguagesforFree"
    "DB6EA5DB.CyberLinkMediaSuiteEssentials"
    "DolbyLaboratories.DolbyAccess"
    "DolbyLaboratories.DolbyAccess"
    "Drawboard.DrawboardPDF"
    "Facebook.Facebook"
    "Fitbit.FitbitCoach"
    "Flipboard.Flipboard"
    "GAMELOFTSA.Asphalt8Airborne"
    "KeeperSecurityInc.Keeper"
    "NORDCURRENT.COOKINGFEVER"
    "PandoraMediaInc.29680B314EFC2"
    "Playtika.CaesarsSlotsFreeCasino"
    "ShazamEntertainmentLtd.Shazam"
    "SlingTVLLC.SlingTV"
    "SpotifyAB.SpotifyMusic"
    "ThumbmunkeysLtd.PhototasticCollage"
    "TuneIn.TuneInRadio"
    "WinZipComputing.WinZipUniversal"
    "XINGAG.XING"
    "flaregamesGmbH.RoyalRevolt2"
    "king.com.*"
    "king.com.BubbleWitch3Saga"
    "king.com.CandyCrushSaga"
    "king.com.CandyCrushSodaSaga"
    "A025C540.Yandex.Music"
    "Microsoft.Advertising.Xaml"
)

$appxprovisionedpackage = Get-AppxProvisionedPackage -Online

foreach ($app in $apps) {
    Write-Output "Trying to remove $app"

    Get-AppxPackage -Name $app -AllUsers | Remove-AppxPackage -AllUsers

    ($appxprovisionedpackage).Where( {$_.DisplayName -EQ $app}) |
        Remove-AppxProvisionedPackage -Online
}

$cdm = @(
    "ContentDeliveryAllowed"
    "FeatureManagementEnabled"
    "OemPreInstalledAppsEnabled"
    "PreInstalledAppsEnabled"
    "PreInstalledAppsEverEnabled"
    "SilentInstalledAppsEnabled"
    "SubscribedContent-314559Enabled"
    "SubscribedContent-338387Enabled"
    "SubscribedContent-338388Enabled"
    "SubscribedContent-338389Enabled"
    "SubscribedContent-338393Enabled"
    "SubscribedContentEnabled"
    "SystemPaneSuggestionsEnabled"
)

New-FolderForced -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
foreach ($key in $cdm) {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" $key 0
}

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" "AutoDownload" 2

New-FolderForced -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" "DisableWindowsConsumerFeatures" 1

Import-Module -DisableNameChecking $PSScriptRoot\..\lib\New-FolderForced.psm1
Import-Module -DisableNameChecking $PSScriptRoot\..\lib\take-own.psm1

Write-Output "Kill OneDrive process"
taskkill.exe /F /IM "OneDrive.exe"
taskkill.exe /F /IM "explorer.exe"

Write-Output "Remove OneDrive"
if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
    & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
}
if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
    & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
}

Write-Output "Removing OneDrive leftovers"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"

If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
}

Write-Output "Disable OneDrive via Group Policies"
New-FolderForced -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

Write-Output "Remove Onedrive from explorer sidebar"
New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
Set-ItemProperty -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
Remove-PSDrive "HKCR"

Write-Output "Removing run hook for new users"
reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
reg unload "hku\Default"

Write-Output "Removing startmenu entry"
Remove-Item -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

Write-Output "Removing scheduled task"
Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

Write-Output "Restarting explorer"
Start-Process "explorer.exe"

Write-Output "Waiting for explorer to complete loading"
Start-Sleep 10

fsutil behavior set DisableLastAccess 1
fsutil behavior set EncryptPagingFile 0

$tasks = @(
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 64 Critical"
    "\Microsoft\Windows\.NET Framework\.NET Framework NGEN v4.0.30319 Critical"
    "\Microsoft\Windows\AppID\SmartScreenSpecific"
    "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
    "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
    "\Microsoft\Windows\Autochk\Proxy"
    "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask"
    "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"
    "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"
    "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"
    "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
    "\Microsoft\Windows\Feedback\Siuf\DmClient"
    "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance"
    "\Microsoft\Windows\Windows Defender\Windows Defender Cleanup"
    "\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan"
    "\Microsoft\Windows\Windows Defender\Windows Defender Verification"

    "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
)

foreach ($task in $tasks) {
    $parts = $task.split('\')
    $name = $parts[-1]
    $path = $parts[0..($parts.length-2)] -join '\'

    Disable-ScheduledTask -TaskName "$name" -TaskPath "$path" -ErrorAction SilentlyContinue
}

Disable-MMAgent -mc
echo "Now you can also disable service SysMain (former Superfetch) in case it's not used."

Disable-MMAgent -ApplicationPreLaunch
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v EnablePrefetcher /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v AllowPrelaunch /t REG_DWORD /d "0" /f

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"

$Script:TweakType = "Backup"

function New-RestorePoint() {
    Write-Status -Types "+", $TweakType -Status "Enabling system drive Restore Point..."
    Enable-ComputerRestore -Drive "$env:SystemDrive\"
    Checkpoint-Computer -Description "Win 10+ SDT Restore Point" -RestorePointType "MODIFY_SETTINGS"
}

function Backup-HostsFile() {
    $PathToHostsFile = "$env:SystemRoot\System32\drivers\etc"

    Write-Status -Types "+", $TweakType -Status "Doing Backup on Hosts file..."
    $Date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
    Push-Location "$PathToHostsFile"

    If (!(Test-Path "$PathToHostsFile\Hosts_Backup")) {
        Write-Status -Types "?", $TweakType -Status "Backup folder not found! Creating a new one..." -Warning
        mkdir -Path "$PathToHostsFile\Hosts_Backup"
    }
    Push-Location "Hosts_Backup"

    Copy-Item -Path ".\..\hosts" -Destination "hosts_$Date"

    Pop-Location
    Pop-Location
}

New-RestorePoint 
Backup-HostsFile 

function Install-DefaultAppsList() {
   
    $Packages = (Get-Item 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications') | Get-ChildItem

    $PackageFilter = $args[0]

    If ([string]::IsNullOrEmpty($PackageFilter)) {
        Write-Warning "No filter specified, attempting to re-register all provisioned apps."
    } Else {
        $Packages = $Packages | Where-Object { $_.Name -like $PackageFilter }

        If ($null -eq $Packages) {
            Write-Warning "No provisioned apps match the specified filter."
            exit
        } Else {
            Write-Host "Registering the provisioned apps that match $PackageFilter..."
        }
    }

    ForEach ($Package in $Packages) {
        
        $PackageName = $Package | Get-ItemProperty | Select-Object -ExpandProperty PSChildName
        $PackagePath = [System.Environment]::ExpandEnvironmentVariables(($Package | Get-ItemProperty | Select-Object -ExpandProperty Path))
    
        Write-Host "Attempting to register package: $PackageName..."
        Add-AppxPackage -register $PackagePath -DisableDevelopmentMode
    }
}

Install-DefaultAppsList

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Open-File.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Unregister-DuplicatedPowerPlan.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\utils\Individual-Tweaks.psm1"

function Optimize-Performance() {
    [CmdletBinding()]
    param(
        [Switch] $Revert,
        [Int]    $Zero = 0,
        [Int]    $One = 1,
        [Array]  $EnableStatus = @(
            @{ Symbol = "-"; Status = "Disabling"; }
            @{ Symbol = "+"; Status = "Enabling"; }
        )
    )
    $TweakType = "Performance"

    If (($Revert)) {
        Write-Status -Types "*", $TweakType -Status "Reverting the tweaks is set to '$Revert'." -Warning
        $Zero = 1
        $One = 0
        $EnableStatus = @(
            @{ Symbol = "*"; Status = "Restoring"; }
            @{ Symbol = "*"; Status = "Re-Disabling"; }
        )
    }

    $PathToLMMultimediaSystemProfile = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
    $PathToLMMultimediaSystemProfileOnGameTasks = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games"
    $PathToLMPoliciesEdge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $PathToLMPoliciesPsched = "HKLM:\SOFTWARE\Policies\Microsoft\Psched"
    $PathToLMPoliciesWindowsStore = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
    $PathToUsersControlPanelDesktop = "Registry::HKEY_USERS\.DEFAULT\Control Panel\Desktop"
    $PathToCUControlPanelDesktop = "HKCU:\Control Panel\Desktop"
    $PathToCUGameBar = "HKCU:\SOFTWARE\Microsoft\GameBar"

    Write-Title "Performance Tweaks"

    Write-Section "System"
    Write-Caption "Display"
    Write-Status -Types "+", $TweakType -Status "Enable Hardware Accelerated GPU Scheduling... (Windows 10 20H1+ - Needs Restart)"
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" -Name "HwSchMode" -Type DWord -Value 2

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Remote Assistance..."
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value $Zero

    Write-Status -Types "-", $TweakType -Status "Disabling Ndu High RAM Usage..."
   
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\ControlSet001\Services\Ndu" -Name "Start" -Type DWord -Value 4


    Write-Status -Types "+", $TweakType -Status "Setting SVCHost to match installed RAM size..."
    $RamInKB = (Get-CimInstance -ClassName Win32_PhysicalMemory | Measure-Object -Property Capacity -Sum).Sum / 1KB
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "SvcHostSplitThresholdInKB" -Type DWord -Value $RamInKB

    Write-Status -Types "*", $TweakType -Status "Enabling Windows Store apps Automatic Updates..."
    If (!(Test-Path "$PathToLMPoliciesWindowsStore")) {
        New-Item -Path "$PathToLMPoliciesWindowsStore" -Force | Out-Null
    }
    If ((Get-Item "$PathToLMPoliciesWindowsStore").GetValueNames() -like "AutoDownload") {
        Remove-ItemProperty -Path "$PathToLMPoliciesWindowsStore" -Name "AutoDownload"
    }

    Write-Section "Microsoft Edge Tweaks"
    Write-Caption "System and Performance"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Edge Startup boost..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesEdge" -Name "StartupBoostEnabled" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) run extensions and apps when Edge is closed..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesEdge" -Name "BackgroundModeEnabled" -Type DWord -Value $Zero

    Write-Section "Power Plan Tweaks"

    Write-Status -Types "+", $TweakType -Status "Setting Power Plan to High Performance..."
    powercfg -SetActive 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c

    Write-Status -Types "+", $TweakType -Status "Creating the Ultimate Performance hidden Power Plan..."
    powercfg -DuplicateScheme e9a42b02-d5df-448d-aa00-03f14749eb61
    Write-Host
    Unregister-DuplicatedPowerPlan
    Enable-Hibernate -Type 'Reduced'

    Write-Section "Network & Internet"
    Write-Status -Types "+", $TweakType -Status "Unlimiting your network bandwidth for all your system..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesPsched" -Name "NonBestEffortLimit" -Type DWord -Value 0
    Set-ItemPropertyVerified -Path "$PathToLMMultimediaSystemProfile" -Name "NetworkThrottlingIndex" -Type DWord -Value 0xffffffff

    Write-Section "System & Apps Timeout behaviors"
    Write-Status -Types "+", $TweakType -Status "Reducing Time to services app timeout to 2s to ALL users..."
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control" -Name "WaitToKillServiceTimeout" -Type DWord -Value 2000 
    Write-Status -Types "*", $TweakType -Status "Don't clear page file at shutdown (takes more time) to ALL users..."
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Type DWord -Value 0 

    Write-Status -Types "+", $TweakType -Status "Reducing mouse hover time events to 10ms..."
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\Mouse" -Name "MouseHoverTime" -Type String -Value "1000" 

    ForEach ($DesktopRegistryPath in @($PathToUsersControlPanelDesktop, $PathToCUControlPanelDesktop)) {
        
        If ($DesktopRegistryPath -eq $PathToUsersControlPanelDesktop) {
            Write-Caption "TO ALL USERS"
        } ElseIf ($DesktopRegistryPath -eq $PathToCUControlPanelDesktop) {
            Write-Caption "TO CURRENT USER"
        }

        Write-Status -Types "+", $TweakType -Status "Don't prompt user to end tasks on shutdown..."
        Set-ItemPropertyVerified -Path "$DesktopRegistryPath" -Name "AutoEndTasks" -Type DWord -Value 1 

        Write-Status -Types "*", $TweakType -Status "Returning 'Hung App Timeout' to default..."
        If ((Get-Item "$DesktopRegistryPath").Property -contains "HungAppTimeout") {
            Remove-ItemProperty -Path "$DesktopRegistryPath" -Name "HungAppTimeout"
        }

        Write-Status -Types "+", $TweakType -Status "Reducing mouse and keyboard hooks timeout to 1s..."
        Set-ItemPropertyVerified -Path "$DesktopRegistryPath" -Name "LowLevelHooksTimeout" -Type DWord -Value 1000 
        Write-Status -Types "+", $TweakType -Status "Reducing animation speed delay to 1ms on Windows 11..."
        Set-ItemPropertyVerified -Path "$DesktopRegistryPath" -Name "MenuShowDelay" -Type DWord -Value 1 
        Write-Status -Types "+", $TweakType -Status "Reducing Time to kill apps timeout to 5s..."
        Set-ItemPropertyVerified -Path "$DesktopRegistryPath" -Name "WaitToKillAppTimeout" -Type DWord -Value 5000 
    }

    Write-Section "Gaming Responsiveness Tweaks"

    If (!$Revert) {
        Disable-XboxGameBarDVRandMode
    } Else {
        Enable-XboxGameBarDVRandMode
    }

    Write-Status -Types "*", $TweakType -Status "Enabling game mode..."
    Set-ItemPropertyVerified -Path "$PathToCUGameBar" -Name "AllowAutoGameMode" -Type DWord -Value 1
    Set-ItemPropertyVerified -Path "$PathToCUGameBar" -Name "AutoGameModeEnabled" -Type DWord -Value 1

    Write-Status -Types "+", $TweakType -Status "Reserving 100% of CPU to Multimedia/Gaming tasks..."
    Set-ItemPropertyVerified -Path "$PathToLMMultimediaSystemProfile" -Name "SystemResponsiveness" -Type DWord -Value 0 
    Write-Status -Types "+", $TweakType -Status "Dedicate more CPU/GPU usage to Gaming tasks..."
    Set-ItemPropertyVerified -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "GPU Priority" -Type DWord -Value 8 # 
    Set-ItemPropertyVerified -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "Priority" -Type DWord -Value 6 
    Set-ItemPropertyVerified -Path "$PathToLMMultimediaSystemProfileOnGameTasks" -Name "Scheduling Category" -Type String -Value "High"
}

If (!$Revert) {
    Optimize-Performance 
} Else {
    Optimize-Performance -Revert
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-ItemVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\utils\Individual-Tweaks.psm1"

function Optimize-Privacy() {
    [CmdletBinding()]
    param(
        [Switch] $Revert,
        [Int]    $Zero = 0,
        [Int]    $One = 1,
        [Array]  $EnableStatus = @(
            @{ Symbol = "-"; Status = "Disabling"; }
            @{ Symbol = "+"; Status = "Enabling"; }
        )
    )
    $TweakType = "Privacy"

    If ($Revert) {
        Write-Status -Types "*", $TweakType -Status "Reverting the tweaks is set to '$Revert'." -Warning
        $Zero = 1
        $One = 0
        $EnableStatus = @(
            @{ Symbol = "*"; Status = "Restoring"; }
            @{ Symbol = "*"; Status = "Re-Disabling"; }
        )
    }

    $PathToLMAutoLogger = "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger"
    $PathToLMDeliveryOptimizationCfg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config"
    $PathToLMPoliciesAdvertisingInfo = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo"
    $PathToLMPoliciesSQMClient = "HKLM:\SOFTWARE\Policies\Microsoft\SQMClient\Windows"
    $PathToLMPoliciesToWifi = "HKLM:\Software\Microsoft\PolicyManager\default\WiFi"
    $PathToLMPoliciesWindowsUpdate = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $PathToLMWindowsTroubleshoot = "HKLM:\SOFTWARE\Microsoft\WindowsMitigation"
    $PathToCUContentDeliveryManager = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    $PathToCUDeviceAccessGlobal = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global"
    $PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $PathToCUInputPersonalization = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $PathToCUInputTIPC = "HKCU:\SOFTWARE\Microsoft\Input\TIPC"
    $PathToCUPoliciesCloudContent = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $PathToCUSiufRules = "HKCU:\SOFTWARE\Microsoft\Siuf\Rules"

    Write-Title "Privacy Tweaks"
    If (!$Revert) {
        Disable-ClipboardHistory
        Disable-ClipboardSyncAcrossDevice
        Disable-Cortana
    } Else {
        Enable-ClipboardHistory
        Enable-ClipboardSyncAcrossDevice
        Enable-Cortana
    }

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) File Explorer Ads (OneDrive, New Features etc.)..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "ShowSyncProviderNotifications" -Type DWord -Value $Zero

    Write-Section "Personalization"
    Write-Caption "Start & Lockscreen"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Show me the windows welcome experience after updates..."
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Get fun facts and tips, etc. on lock screen'..."

    $ContentDeliveryManagerDisableOnZero = @(
        "SubscribedContent-310093Enabled"
        "SubscribedContent-314559Enabled"
        "SubscribedContent-314563Enabled"
        "SubscribedContent-338387Enabled"
        "SubscribedContent-338388Enabled"
        "SubscribedContent-338389Enabled"
        "SubscribedContent-338393Enabled"
        "SubscribedContent-353698Enabled"
        "RotatingLockScreenOverlayEnabled"
        "RotatingLockScreenEnabled"
        "ContentDeliveryAllowed"
        "FeatureManagementEnabled"
        "OemPreInstalledAppsEnabled"
        "PreInstalledAppsEnabled"
        "PreInstalledAppsEverEnabled"
        "RemediationRequired"
        "SilentInstalledAppsEnabled"
        "SoftLandingEnabled"
        "SubscribedContentEnabled"
        "SystemPaneSuggestionsEnabled"
    )

    Write-Status -Types "?", $TweakType -Status "From Path: $PathToCUContentDeliveryManager" -Warning
    ForEach ($Name in $ContentDeliveryManagerDisableOnZero) {
        Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) $($Name): $Zero"
        Set-ItemPropertyVerified -Path "$PathToCUContentDeliveryManager" -Name "$Name" -Type DWord -Value $Zero
    }

    Write-Status -Types "-", $TweakType -Status "Disabling 'Suggested Content in the Settings App'..."
    Remove-ItemVerified -Path "$PathToCUContentDeliveryManager\Subscriptions" -Recurse

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Show Suggestions' in Start..."
    Remove-ItemVerified -Path "$PathToCUContentDeliveryManager\SuggestedApps" -Recurse

    Write-Section "Privacy -> Windows Permissions"
    Write-Caption "General"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Let apps use my advertising ID..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesAdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Let websites provide locally relevant content by accessing my language list'..."
    Set-ItemPropertyVerified -Path "HKCU:\Control Panel\International\User Profile" -Name "HttpAcceptLanguageOptOut" -Type DWord -Value $One

    Write-Caption "Speech"
    If (!$Revert) {
        Disable-OnlineSpeechRecognition
    } Else {
        Enable-OnlineSpeechRecognition
    }

    Write-Caption "Inking & Typing Personalization"
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUInputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUInputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value $One
    Set-ItemPropertyVerified -Path "$PathToCUInputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value $One

    Write-Caption "Diagnostics & Feedback"
    If (!$Revert) {
        Disable-Telemetry
    } Else {
        Enable-Telemetry
    }

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) send inking and typing data to Microsoft..."
    Set-ItemPropertyVerified -Path "$PathToCUInputTIPC" -Name "Enabled" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Improve Inking & Typing Recognition..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" -Name "AllowLinguisticDataCollection" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) View diagnostic data..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Diagnostics\DiagTrack\EventTranscriptKey" -Name "EnableEventTranscript" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) feedback frequency..."
    If ((Test-Path "$PathToCUSiufRules\PeriodInNanoSeconds")) {
        Remove-ItemProperty -Path "$PathToCUSiufRules" -Name "PeriodInNanoSeconds"
    }
    Set-ItemPropertyVerified -Path "$PathToCUSiufRules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value $Zero

    Write-Caption "Activity History"
    If ($Revert) {
        Enable-ActivityHistory
    } Else {
        Disable-ActivityHistory
    }

    Write-Section "Privacy -> Apps Permissions"
    Write-Caption "Location"
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Value "Deny"
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "EnableStatus" -Type DWord -Value $Zero

    Write-Caption "Notifications"
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" -Name "Value" -Value "Deny"

    Write-Caption "App Diagnostics"
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny"
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" -Name "Value" -Value "Deny"

    Write-Caption "Account Info Access"
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny"
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" -Name "Value" -Value "Deny"

    Write-Caption "Other Devices"
    Write-Status -Types "-", $TweakType -Status "Denying device access..."
    Set-ItemPropertyVerified -Path "$PathToCUDeviceAccessGlobal\LooselyCoupled" -Name "Value" -Value "Deny"
    ForEach ($key in (Get-ChildItem "$PathToCUDeviceAccessGlobal")) {
        If ($key.PSChildName -EQ "LooselyCoupled") {
            Continue
        }
        Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Setting $($key.PSChildName) value to 'Deny' ..."
        Set-ItemPropertyVerified -Path ("$PathToCUDeviceAccessGlobal\" + $key.PSChildName) -Name "Value" -Value "Deny"
    }

    Write-Caption "Background Apps"
    Enable-BackgroundAppsToogle

    Write-Section "Update & Security"
    Write-Caption "Windows Update"
    Enable-AutomaticWindowsUpdate

    Write-Status -Types "*", $TweakType -Status "Enabling Automatic Updates..."
    
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesWindowsUpdate" -Name "NoAutoUpdate" -Type DWord -Value 0

    Write-Status -Types "+", $TweakType -Status "Setting Scheduled Day to Every day..."

    Set-ItemPropertyVerified -Path "$PathToLMPoliciesWindowsUpdate" -Name "ScheduledInstallDay" -Type DWord -Value 0

    Write-Status -Types "-", $TweakType -Status "Setting Scheduled time to 03h00m..."

    Set-ItemPropertyVerified -Path "$PathToLMPoliciesWindowsUpdate" -Name "ScheduledInstallTime" -Type DWord -Value 3

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Automatic Reboot after update..."
 
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesWindowsUpdate" -Name "NoAutoRebootWithLoggedOnUsers" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Change Windows Updates to 'Notify to schedule restart'..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" -Name "UxOption" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Restricting Windows Update P2P downloads for Local Network only..."

    Set-ItemPropertyVerified -Path "$PathToLMDeliveryOptimizationCfg" -Name "DODownloadMode" -Type DWord -Value $One

    Write-Caption "Troubleshooting"
    Write-Status -Types "+", $TweakType -Status "Enabling Automatic Recommended Troubleshooting, then notify me..."
    Set-ItemPropertyVerified -Path "$PathToLMWindowsTroubleshoot" -Name "UserPreference" -Type DWord -Value 3

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Windows Spotlight Features..."
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "ConfigureWindowsSpotlight" -Type DWord -Value 2
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "IncludeEnterpriseSpotlight" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightFeatures" -Type DWord -Value $One
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnActionCenter" -Type DWord -Value $One
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightOnSettings" -Type DWord -Value $One
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsSpotlightWindowsWelcomeExperience" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Tailored Experiences..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" -Name "TailoredExperiencesWithDiagnosticDataEnabled" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Third Party Suggestions..."
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "DisableThirdPartySuggestions" -Type DWord -Value $One
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesCloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value $One

    Write-Status -Types "+", $TweakType -Status "Enabling Windows Update to search Drivers..."

    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" -Name "SearchOrderConfig" -Type DWord -Value 1
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) enhanced icons and manufacturer apps (escape from broken drivers and bloatware)..."

    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" -Name "PreventDeviceMetadataFromNetwork" -Type DWord -Value $One
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesSQMClient" -Name "CEIPEnable" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "AITEnable" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat" -Name "DisableUAR" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) some startup event traces (AutoLoggers)..."
    Set-ItemPropertyVerified -Path "$PathToLMAutoLogger\AutoLogger-Diagtrack-Listener" -Name "Start" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToLMAutoLogger\SQMLogger" -Name "Start" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: HotSpot Sharing'..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesToWifi\AllowWiFiHotSpotReporting" -Name "value" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'WiFi Sense: Shared HotSpot Auto-Connect'..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesToWifi\AllowAutoConnectToWiFiSenseHotspots" -Name "value" -Type DWord -Value $Zero

    Write-Caption "Deleting useless registry keys..."
    $KeysToDelete = @(
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )

    ForEach ($Key in $KeysToDelete) {
        Remove-ItemVerified $Key -Recurse
    }
}

If (!$Revert) {
    Optimize-Privacy
} Else {
    Optimize-Privacy -Revert
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Get-HardwareInfo.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\utils\Individual-Tweaks.psm1"

function Optimize-Security() {
    $TweakType = "Security"

    $PathToLMPoliciesEdge = "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge"
    $PathToLMPoliciesMRT = "HKLM:\SOFTWARE\Policies\Microsoft\MRT"
    $PathToCUExplorer = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"

    Write-Title "Security Tweaks"

    Write-Section "Windows Firewall"
    Write-Status -Types "+", $TweakType -Status "Enabling default firewall profiles..."
    Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled True

    Write-Section "Windows Defender"
    Write-Status -Types "?", $TweakType -Status "If you already use another antivirus, nothing will happen." -Warning
    Write-Status -Types "+", $TweakType -Status "Ensuring your Windows Defender is ENABLED..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -Type DWORD -Value 0
    Set-MpPreference -DisableRealtimeMonitoring $false -Force

    Write-Status -Types "+", $TweakType -Status "Enabling Microsoft Defender Exploit Guard network protection..."
    Set-MpPreference -EnableNetworkProtection Enabled -Force

    Write-Status -Types "+", $TweakType -Status "Enabling detection for potentially unwanted applications and block them..."
    Set-MpPreference -PUAProtection Enabled -Force

    Write-Section "SmartScreen"
    Write-Status -Types "+", $TweakType -Status "Enabling 'SmartScreen' for Microsoft Edge..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesEdge\PhishingFilter" -Name "EnabledV9" -Type DWord -Value 1

    Write-Status -Types "+", $TweakType -Status "Enabling 'SmartScreen' for Store Apps..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" -Name "EnableWebContentEvaluation" -Type DWord -Value 1

    Write-Section "Old SMB Protocol"
    Write-Status -Types "+", $TweakType -Status "Disabling SMB 1.0 protocol..."
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

    Write-Section "Old .NET cryptography"

    Write-Status -Types "+", $TweakType -Status "Enabling .NET strong cryptography..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319" -Name "SchUseStrongCrypto" -Type DWord -Value 1

    Write-Section "Autoplay and Autorun (Removable Devices)"
    Write-Status -Types "-", $TweakType -Status "Disabling Autoplay..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

    Write-Status -Types "-", $TweakType -Status "Disabling Autorun for all Drives..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

    Write-Section "Microsoft Store"
    Disable-SearchAppForUnknownExt

    Write-Section "Windows Explorer"
    Write-Status -Types "+", $TweakType -Status "Enabling Show file extensions in Explorer..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "HideFileExt" -Type DWord -Value 0

    Write-Section "User Account Control (UAC)"

    Write-Status -Types "+", $TweakType -Status "Raising UAC level..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1

    Write-Section "Windows Update"

    Write-Status -Types "+", $TweakType -Status "Enabling offer Malicious Software Removal Tool via Windows Update..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesMRT" -Name "DontOfferThroughWUAU" -Type DWord -Value 0

    Write-Status -Types "?", $TweakType -Status "For more tweaks, edit the '$PSCommandPath' file, then uncomment '#SomethingHere' code lines" -Warning
}

Optimize-Security 

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Get-HardwareInfo.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ServiceStartup.psm1"

function Optimize-ServicesRunning() {
    [CmdletBinding()]
    param (
        [Switch] $Revert
    )

    $IsSystemDriveSSD = $(Get-OSDriveType) -eq "SSD"
    $EnableServicesOnSSD = @("SysMain", "WSearch")

    $ServicesToDisabled = @(
        "DiagTrack"                                 
        "diagnosticshub.standardcollector.service"  
        "dmwappushservice"                         
        "Fax"                                      
        "fhsvc"                                     
        "GraphicsPerfSvc"                           
        "HomeGroupListener"                         
        "HomeGroupProvider"                         
        "lfsvc"                                     
        "MapsBroker"                                
        "PcaSvc"                                    
        "RemoteAccess"                              
        "RemoteRegistry"                            
        "RetailDemo"                                
        "SysMain"                                   
        "TrkWks"                                    
        "WSearch"                                   

    )

    $ServicesToManual = @(
        "BITS"                           
        "edgeupdate"                     
        "edgeupdatem"                    
        "FontCache"                      
        "PhoneSvc"                       
        "SCardSvr"                       
        "stisvc"                         
        "WbioSrvc"                       
        "wisvc"                          
        "WMPNetworkSvc"                  
        "WpnService"                     
        "BTAGService"                    
        "BthAvctpSvc"                    
        "bthserv"                        
        "RtkBtManServ"                   
        "DPS"                            
        "WdiServiceHost"                 
        "WdiSystemHost"                  
        "iphlpsvc"                      
        "lmhosts"                        
        "ndu"                            
        "SharedAccess"                   
        "Wecsvc"                        
        "WerSvc"                        
        "XblAuthManager"                 
        "XblGameSave"                    
        "XboxGipSvc"                     
        "XboxNetApiSvc"                  
        "gupdate"                        
        "gupdatem"                       
    )

    Write-Title "Services tweaks"
    Write-Section "Disabling services from Windows"

    If ($Revert) {
        Write-Status -Types "*", "Service" -Status "Reverting the tweaks is set to '$Revert'." -Warning
        Set-ServiceStartup -State 'Manual' -Services $ServicesToDisabled -Filter $EnableServicesOnSSD
    } Else {
        Set-ServiceStartup -State 'Disabled' -Services $ServicesToDisabled -Filter $EnableServicesOnSSD
    }

    Write-Section "Enabling services from Windows"

    If ($IsSystemDriveSSD -or $Revert) {
        Set-ServiceStartup -State 'Automatic' -Services $EnableServicesOnSSD
    }

    Set-ServiceStartup -State 'Manual' -Services $ServicesToManual
}


If (!$Revert) {
    Optimize-ServicesRunning 
} Else {
    Optimize-ServicesRunning -Revert
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ScheduledTaskState.psm1"

function Optimize-TaskScheduler() {
    [CmdletBinding()]
    param (
        [Switch] $Revert
    )

    $DisableScheduledTasks = @(
        "\Microsoft\Office\OfficeTelemetryAgentLogOn"
        "\Microsoft\Office\OfficeTelemetryAgentFallBack"
        "\Microsoft\Office\Office 15 Subscription Heartbeat"
        "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"
        "\Microsoft\Windows\Application Experience\ProgramDataUpdater"
        "\Microsoft\Windows\Application Experience\StartupAppTask"
        "\Microsoft\Windows\Autochk\Proxy"
        "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator"        
        "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"       
        "\Microsoft\Windows\Customer Experience Improvement Program\Uploader"
        "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"             
        "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector"
        "\Microsoft\Windows\Location\Notifications"                                      
        "\Microsoft\Windows\Location\WindowsActionDialog"                               
        "\Microsoft\Windows\Maps\MapsToastTask"                                         
        "\Microsoft\Windows\Maps\MapsUpdateTask"                                        
        "\Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser"              
        "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem"               
        "\Microsoft\Windows\Retail Demo\CleanupOfflineContent"                           
        "\Microsoft\Windows\Shell\FamilySafetyMonitor"                                   
        "\Microsoft\Windows\Shell\FamilySafetyRefreshTask"                                
        "\Microsoft\Windows\Shell\FamilySafetyUpload"                   
    )

    $EnableScheduledTasks = @(
        "\Microsoft\Windows\Defrag\ScheduledDefrag"                 
        "\Microsoft\Windows\Maintenance\WinSAT"                     
        "\Microsoft\Windows\RecoveryEnvironment\VerifyWinRE"        
        "\Microsoft\Windows\Windows Error Reporting\QueueReporting"
    )

    Write-Title "Task Scheduler tweaks"
    Write-Section "Disabling Scheduled Tasks from Windows"

    If ($Revert) {
        Write-Status -Types "*", "TaskScheduler" -Status "Reverting the tweaks is set to '$Revert'." -Warning
        Set-ScheduledTaskState -State 'Enabled' -ScheduledTask $DisableScheduledTasks
    } Else {
        Set-ScheduledTaskState -State 'Disabled' -ScheduledTask $DisableScheduledTasks
    }

    Write-Section "Enabling Scheduled Tasks from Windows"
    Set-ScheduledTaskState -State 'Enabled' -ScheduledTask $EnableScheduledTasks
}

If (!$Revert) {
    Optimize-TaskScheduler 
} Else {
    Optimize-TaskScheduler -Revert
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-OptionalFeatureState.psm1"

function Optimize-WindowsFeaturesList() {
    [CmdletBinding()]
    param (
        [Switch] $Revert
    )

    $DisableFeatures = @(
        "FaxServicesClientPackage"            
        "IIS-*"                                
        "Internet-Explorer-Optional-*"         
        "LegacyComponents"                     
        "MediaPlayback"                        
        "MicrosoftWindowsPowerShellV2"         
        "MicrosoftWindowsPowershellV2Root"    
        "Printing-PrintToPDFServices-Features" 
        "Printing-XPSServices-Features"       
        "WorkFolders-Client"                   
    )

    $EnableFeatures = @(
        "NetFx3"                            
        "NetFx4-AdvSrvs"                   
        "NetFx4Extended-ASPNET45"           
    )

    Write-Title "Optional Features Tweaks"
    Write-Section "Uninstall Optional Features from Windows"

    If ($Revert) {
        Write-Status -Types "*", "OptionalFeature" -Status "Reverting the tweaks is set to '$Revert'." -Warning
        Set-OptionalFeatureState -State 'Enabled' -OptionalFeatures $DisableFeatures
    } Else {
        Set-OptionalFeatureState -State 'Disabled' -OptionalFeatures $DisableFeatures
    }

    Write-Section "Install Optional Features from Windows"
    Set-OptionalFeatureState -State 'Enabled' -OptionalFeatures $EnableFeatures
}

If (!$Revert) {
    Optimize-WindowsFeaturesList 
} Else {
    Optimize-WindowsFeaturesList -Revert
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Get-HardwareInfo.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Open-File.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-ItemVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\utils\Individual-Tweaks.psm1"

function Register-PersonalTweaksList() {
    [CmdletBinding()]
    param (
        [Switch] $Revert,
        [Int]    $Zero = 0,
        [Int]    $One = 1,
        [Array]  $EnableStatus = @(
            @{ Symbol = "-"; Status = "Disabling"; }
            @{ Symbol = "+"; Status = "Enabling"; }
        )
    )
    $TweakType = "Personal"

    If ($Revert) {
        Write-Status -Types "*", $TweakType -Status "Reverting the tweaks is set to '$Revert'." -Warning
        $Zero = 1
        $One = 0
        $EnableStatus = @(
            @{ Symbol = "*"; Status = "Restoring"; }
            @{ Symbol = "*"; Status = "Re-Disabling"; }
        )
    }

    $PathToCUAccessibility = "HKCU:\Control Panel\Accessibility"
    $PathToCUPoliciesEdge = "HKCU:\SOFTWARE\Policies\Microsoft\Edge"
    $PathToCUExplorer = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer"
    $PathToCUExplorerAdvanced = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced"
    $PathToCUPoliciesExplorer = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer"
    $PathToCUPoliciesLiveTiles = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"
    $PathToCUNewsAndInterest = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds"
    $PathToCUWindowsSearch = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search"
    $PathToLMPoliciesEdge = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
    $PathToLMPoliciesExplorer = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    $PathToLMPoliciesNewsAndInterest = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds"
    $PathToLMPoliciesWindowsSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    $PathToLMRemovableDevices = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\DelegateFolders\{F5FB2C77-0E2F-4A16-A381-3E560C68BC83}"

    Write-Title "My Personal Tweaks"
    If (!$Revert) {
        $Scripts = @("enable-photo-viewer.reg")
        Enable-DarkTheme
        Enable-LegacyContextMenu
    } Else {
        $Scripts = @("disable-photo-viewer.reg")
        Disable-DarkTheme
        Disable-LegacyContextMenu
    }
    Open-RegFilesCollection -RelativeLocation "src\utils" -Scripts $Scripts -NoDialog

    If ((Get-SystemSpec)[2] -like '*Windows 10*') {
        Write-Status -Types "+", $TweakType -Status "Fixing .URL file association with Internet Browser..."

        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\DefaultIcon" -Name "(default)" -Type ExpandString -Value "C:\Windows\System32\url.dll,5"
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\Shell\Open" -Name "CLSID" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\Shell\Open" -Name "LegacyDisable" -Type String -Value ""
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\Shell\Open\Command" -Name "(default)" -Type String -Value "`"C:\Windows\System32\rundll32.exe`" `"C:\Windows\System32\ieframe.dll`",OpenURL %l"
        New-Item -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\ShellEx" -Force | Out-Null
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\ShellEx\{000214EE-0000-0000-C000-000000000046}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\ShellEx\{000214F9-0000-0000-C000-000000000046}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\ShellEx\{00021500-0000-0000-C000-000000000046}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\ShellEx\{CABB0DA0-DA57-11CF-9974-0020AFD79762}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Classes\IE.AssocFile.URL\ShellEx\{FBF23B80-E3F0-101B-8488-00AA003E56F8}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"

        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url" -Name "(default)" -Type String -Value "InternetShortcut"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url\OpenWithProgIds" -Name "InternetShortcut" -Type String -Value ""
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url\PersistentHandler" -Name "(default)" -Type String -Value "{8CD34779-9F10-4f9b-ADFB-B3FAEABDAB5A}"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url\ShellEx\{000214EE-0000-0000-C000-000000000046}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url\ShellEx\{000214F9-0000-0000-C000-000000000046}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url\ShellEx\{00021500-0000-0000-C000-000000000046}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url\ShellEx\{CABB0DA0-DA57-11CF-9974-0020AFD79762}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\.url\ShellEx\{FBF23B80-E3F0-101B-8488-00AA003E56F8}" -Name "(default)" -Type String -Value "{FBF23B40-E3F0-101B-8488-00AA003E56F8}"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\InternetShortcut" -Name "(default)" -Type String -Value "InternetShortcut"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\InternetShortcut\DefaultIcon" -Name "(default)" -Type ExpandString -Value "%SystemRoot%\System32\url.dll,5"
        Set-ItemPropertyVerified -Path "Registry::HKEY_CLASSES_ROOT\InternetShortcut\tabsets" -Name "selection" -Type DWord -Value 0x00000705

        New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\OpenWithList" -Force | Out-Null
        Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\OpenWithProgids" -Name "InternetShortcut" -Type None -Value ([byte[]]@())
        Open-RegFilesCollection -RelativeLocation "src\utils" -Scripts "fix-url-association.reg" -NoDialog
        Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\UserChoice" -Name "Hash" -Type String -Value "wMx4BywX2RI="
        Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.url\UserChoice" -Name "ProgId" -Type String -Value "IE.AssocFile.URL"
        Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\Roaming\OpenWith\FileExts\.url\UserChoice" -Name "Hash" -Type String -Value "wMx4BywX2RI="
        Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\Roaming\OpenWith\FileExts\.url\UserChoice" -Name "ProgId" -Type String -Value "IE.AssocFile.URL"
    }

    If ((Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name CurrentBuild).CurrentBuild -lt 22557) {
        Write-Status -Types "+", $TweakType -Status "Showing task manager details..."
        $taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
        Do {
            Start-Sleep -Milliseconds 100
            $preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
        } Until ($preferences)
        Stop-Process $taskmgr
        $preferences.Preferences[28] = 0
        Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences
    } Else {
        Write-Status -Types "?", $TweakType -Status "Task Manager patch not run in builds 22557+ due to bug" -Warning
    }

    Write-Section "Windows Explorer Tweaks"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Quick Access from Windows Explorer..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorer" -Name "ShowFrequent" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUExplorer" -Name "ShowRecent" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUExplorer" -Name "HubMode" -Type DWord -Value $One

    Write-Status -Types "-", $TweakType -Status "Removing 3D Objects from This PC..."
    Remove-ItemVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse
    Remove-ItemVerified -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse

    Write-Status -Types "-", $TweakType -Status "Removing 'Edit with Paint 3D' from the Context Menu..."
    $Paint3DFileTypes = @(".3mf", ".bmp", ".fbx", ".gif", ".jfif", ".jpe", ".jpeg", ".jpg", ".png", ".tif", ".tiff")
    ForEach ($FileType in $Paint3DFileTypes) {
        Write-Status -Types "-", $TweakType -Status "Removing Paint 3D from file type: $FileType"
        Remove-ItemVerified -Path "Registry::HKEY_CLASSES_ROOT\SystemFileAssociations\$FileType\Shell\3D Edit" -Recurse
    }

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Show Drives without Media..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "HideDrivesWithNoMedia" -Type DWord -Value $Zero

    Write-Status -Types "*", $TweakType -Status "Restoring Aero-Shake Minimize feature..."
    Remove-ItemProperty -Path "$PathToCUExplorerAdvanced" -Name "DisallowShaking" -Force -ErrorAction SilentlyContinue

    Write-Status -Types "+", $TweakType -Status "Setting Windows Explorer to start on This PC instead of Quick Access..."

    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "LaunchTo" -Type DWord -Value 1

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Show hidden files in Explorer..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "Hidden" -Type DWord -Value $One

    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) Showing file transfer details..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value $One

    Write-Status -Types "-", $TweakType -Status "Disabling '- Shortcut' name after creating a shortcut..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorer" -Name "link" -Type Binary -Value ([byte[]](0x00, 0x00, 0x00, 0x00))

    Write-Status -Types "-", $TweakType -Status "Hiding duplicated Removable Devices on Navigation Pane..."
    Remove-ItemVerified -Path $PathToLMRemovableDevices -Recurse

    Write-Status -Types "*", $TweakType -Status "Disabling expand to folder in Navigation Pane..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "NavPaneExpandToCurrentFolder" -Type DWord -Value 0

    Write-Section "Task Bar Tweaks"
    Write-Caption "Task Bar - Windows 10 Compatible"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) the 'Search Box' from taskbar..."

    Set-ItemPropertyVerified -Path "$PathToCUWindowsSearch" -Name "SearchboxTaskbarMode" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Windows search highlights from taskbar..."
    Set-ItemPropertyVerified -Path "$PathToLMPoliciesWindowsSearch" -Name "EnableDynamicContentInWSB" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) the 'Task View' icon from taskbar..."
  
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "ShowTaskViewButton" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Open on Hover from 'News and Interest' from taskbar..."

    Set-ItemPropertyVerified -Path "$PathToCUNewsAndInterest" -Name "ShellFeedsTaskbarOpenOnHover" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'News and Interest' from taskbar..."

    Set-ItemPropertyVerified -Path "$PathToLMPoliciesNewsAndInterest" -Name "EnableFeeds" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'People' icon from taskbar..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced\People" -Name "PeopleBand" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Live Tiles..."
    Set-ItemPropertyVerified -Path $PathToCUPoliciesLiveTiles -Name "NoTileApplicationNotification" -Type DWord -Value $One

    Write-Status -Types "*", $TweakType -Status "Enabling Auto tray icons..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorer" -Name "EnableAutoTray" -Type DWord -Value 1

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Meet now' icon on taskbar..."

    Set-ItemPropertyVerified -Path "$PathToLMPoliciesExplorer" -Name "HideSCAMeetNow" -Type DWord -Value $One

    Write-Caption "Task Bar - Windows 11 Compatible"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Widgets' icon from taskbar..."

    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "TaskbarDa" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) 'Chat' icon from taskbar..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "TaskbarMn" -Type DWord -Value $Zero

    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) creation of Thumbs.db thumbnail cache files..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "DisableThumbnailCache" -Type DWord -Value $One
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "DisableThumbsDBOnNetworkFolders" -Type DWord -Value $One

    Write-Caption "Colors"
    Write-Status -Types "*", $TweakType -Status "Restoring taskbar transparency..."
    Set-ItemPropertyVerified -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -Type DWord -Value 1

    Write-Section "System"
    Write-Caption "Multitasking"
    Write-Status -Types "-", $TweakType -Status "Disabling Edge multi tabs showing on Alt + Tab..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "MultiTaskingAltTabFilter" -Type DWord -Value 3

    Write-Section "Devices"
    Write-Caption "Bluetooth & other devices"
    Write-Status -Types $EnableStatus[1].Symbol, $TweakType -Status "$($EnableStatus[1].Status) driver download over metered connections..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceSetup" -Name "CostedNetworkPolicy" -Type DWord -Value $One

    Write-Section "Personalization"
    Write-Caption "Start"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Most Recent Used (MRU) items in Start, Jump Lists and File Explorer..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "Start_TrackDocs" -Type DWord -Value $Zero

    Write-Section "Privacy"
    Write-Caption "General"
    Write-Status -Types "*", $TweakType -Status "Enabling Let Windows track app launches to improve Start and search results (Run Dialog History)..."
    Set-ItemPropertyVerified -Path "$PathToCUExplorerAdvanced" -Name "Start_TrackProgs" -Type DWord -Value 1

    Write-Section "Cortana Tweaks"
    Write-Status -Types $EnableStatus[0].Symbol, $TweakType -Status "$($EnableStatus[0].Status) Bing Search in Start Menu..."
    Set-ItemPropertyVerified -Path "$PathToCUWindowsSearch" -Name "BingSearchEnabled" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUWindowsSearch" -Name "CortanaConsent" -Type DWord -Value $Zero
    Set-ItemPropertyVerified -Path "$PathToCUPoliciesExplorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value $One

    Write-Section "Ease of Access"
    Write-Caption "Keyboard"
    Write-Status -Types "-", $TweakType -Status "Disabling Sticky Keys..."
    Set-ItemPropertyVerified -Path "$PathToCUAccessibility\StickyKeys" -Name "Flags" -Value "506"
    Set-ItemPropertyVerified -Path "$PathToCUAccessibility\Keyboard Response" -Name "Flags" -Value "122"
    Set-ItemPropertyVerified -Path "$PathToCUAccessibility\ToggleKeys" -Name "Flags" -Value "58"

    Write-Section "Microsoft Edge Policies"
    Write-Caption "Privacy, search and services -> Address bar and search"
    Write-Status -Types "*", $TweakType -Status "Show me search and site suggestions using my typed characters..."
    Remove-ItemProperty -Path "$PathToCUPoliciesEdge", "$PathToLMPoliciesEdge" -Name "SearchSuggestEnabled" -Force -ErrorAction SilentlyContinue

    Write-Status -Types "*", $TweakType -Status "Show me history and favorite suggestions and other data using my typed characters..."
    Remove-ItemProperty -Path "$PathToCUPoliciesEdge", "$PathToLMPoliciesEdge" -Name "LocalProvidersEnabled" -Force -ErrorAction SilentlyContinue

    Write-Status -Types "*", $TweakType -Status "Restoring Error reporting..."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 0

    Write-Status -Types "+", $TweakType -Status "Bringing back F8 alternative Boot Modes..."
    bcdedit /set `{current`} bootmenupolicy Legacy

    Write-Section "Power Plan Tweaks"
    $TimeoutScreenBattery = 5
    $TimeoutScreenPluggedIn = 10

    $TimeoutStandByBattery = 15
    $TimeoutStandByPluggedIn = 180

    $TimeoutDiskBattery = 20
    $TimeoutDiskPluggedIn = 30

    $TimeoutHibernateBattery = 15
    $TimeoutHibernatePluggedIn = 15

    Write-Status -Types "+", $TweakType -Status "Setting the Monitor Timeout to AC: $TimeoutScreenPluggedIn and DC: $TimeoutScreenBattery..."
    powercfg -Change Monitor-Timeout-AC $TimeoutScreenPluggedIn
    powercfg -Change Monitor-Timeout-DC $TimeoutScreenBattery

    Write-Status -Types "+", $TweakType -Status "Setting the Standby Timeout to AC: $TimeoutStandByPluggedIn and DC: $TimeoutStandByBattery..."
    powercfg -Change Standby-Timeout-AC $TimeoutStandByPluggedIn
    powercfg -Change Standby-Timeout-DC $TimeoutStandByBattery

    Write-Status -Types "+", $TweakType -Status "Setting the Disk Timeout to AC: $TimeoutDiskPluggedIn and DC: $TimeoutDiskBattery..."
    powercfg -Change Disk-Timeout-AC $TimeoutDiskPluggedIn
    powercfg -Change Disk-Timeout-DC $TimeoutDiskBattery

    Write-Status -Types "+", $TweakType -Status "Setting the Hibernate Timeout to AC: $TimeoutHibernatePluggedIn and DC: $TimeoutHibernateBattery..."
    powercfg -Change Hibernate-Timeout-AC $TimeoutHibernatePluggedIn
    powercfg -Change Hibernate-Timeout-DC $TimeoutHibernateBattery
}

If (!$Revert) {
    Register-PersonalTweaksList 
} Else {
    Register-PersonalTweaksList -Revert
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-UWPApp.psm1"

function Remove-BloatwareAppsList() {
    $MSApps = @(
        "Microsoft.3DBuilder"                    
        "Microsoft.549981C3F5F10"                
        "Microsoft.Appconnector"
        "Microsoft.BingFinance"                  
        "Microsoft.BingFoodAndDrink"            
        "Microsoft.BingHealthAndFitness"        
        "Microsoft.BingNews"                     
        "Microsoft.BingSports"                   
        "Microsoft.BingTranslator"               
        "Microsoft.BingTravel"                   
        "Microsoft.BingWeather"                  
        "Microsoft.CommsPhone"
        "Microsoft.ConnectivityStore"
        "Microsoft.GetHelp"
        "Microsoft.Getstarted"
        "Microsoft.Messaging"
        "Microsoft.Microsoft3DViewer"
        "Microsoft.MicrosoftOfficeHub"
        "Microsoft.MicrosoftPowerBIForWindows"
        "Microsoft.MicrosoftSolitaireCollection" 
        "Microsoft.MixedReality.Portal"
        "Microsoft.NetworkSpeedTest"
        "Microsoft.Office.OneNote"               
        "Microsoft.Office.Sway"
        "Microsoft.OneConnect"
        "Microsoft.People"                       
        "Microsoft.MSPaint"                      
        "Microsoft.Print3D"                      
        "Microsoft.SkypeApp"                     
        "Microsoft.Todos"                       
        "Microsoft.Wallet"
        "Microsoft.Whiteboard"                   
        "Microsoft.WindowsAlarms"                
        "microsoft.windowscommunicationsapps"
        "Microsoft.WindowsFeedbackHub"           
        "Microsoft.WindowsMaps"                  
        "Microsoft.WindowsPhone"
        "Microsoft.WindowsReadingList"
        "Microsoft.WindowsSoundRecorder"         
        "Microsoft.XboxApp"                      
        "Microsoft.YourPhone"                    
        "Microsoft.ZuneMusic"                   
        "Microsoft.ZuneVideo"                   
        "Microsoft.Advertising.Xaml"
        "Clipchamp.Clipchamp"				     
        "MicrosoftWindows.Client.WebExperience"  
        "MicrosoftTeams"                        

    )

    $ThirdPartyApps = @(
        "*ACGMediaPlayer*"
        "*ActiproSoftwareLLC*"
        "*AdobePhotoshopExpress*"           
        "Amazon.com.Amazon"                 
        "*Asphalt8Airborne*"                
        "*AutodeskSketchBook*"
        "*BubbleWitch3Saga*"               
        "*CaesarsSlotsFreeCasino*"
        "*CandyCrush*"                      
        "*COOKINGFEVER*"
        "*CyberLinkMediaSuiteEssentials*"
        "*DisneyMagicKingdoms*"
        "*Dolby*"                           
        "*DrawboardPDF*"
        "*Duolingo-LearnLanguagesforFree*"  
        "*EclipseManager*"
        "*FarmVille2CountryEscape*"
        "*FitbitCoach*"
        "*Flipboard*"                       
        "*HiddenCity*"
        "*Keeper*"
        "*LinkedInforWindows*"
        "*MarchofEmpires*"
        "*NYTCrossword*"
        "*OneCalendar*"
        "*PandoraMediaInc*"
        "*PhototasticCollage*"
        "*PicsArt-PhotoStudio*"
        "*PolarrPhotoEditorAcademicEdition*"
        "*RoyalRevolt*"                     
        "*Shazam*"
        "*Sidia.LiveWallpaper*"             
        "*Speed Test*"
        "*Sway*"
        "*WinZipUniversal*"
        "*Wunderlist*"
        "*XING*"
    )

    $ManufacturerApps = @(
    
        "DB6EA5DB.MediaSuiteEssentialsforDell"
        "DB6EA5DB.PowerDirectorforDell"
        "DB6EA5DB.Power2GoforDell"
        "DB6EA5DB.PowerMediaPlayerforDell"
        "DellInc.DellCustomerConnect"           
        "DellInc.DellDigitalDelivery"           
        "DellInc.DellHelpSupport"
        "DellInc.DellProductRegistration"
        "DellInc.MyDell"                       
        "SAMSUNGELECTRONICSCO.LTD.1412377A9806A"
        "SAMSUNGELECTRONICSCO.LTD.NewVoiceNote"
        "SAMSUNGELECTRONICSCoLtd.SamsungNotes"
        "SAMSUNGELECTRONICSCoLtd.SamsungFlux"
        "SAMSUNGELECTRONICSCO.LTD.StudioPlus"
        "SAMSUNGELECTRONICSCO.LTD.SamsungWelcome"
        "SAMSUNGELECTRONICSCO.LTD.SamsungUpdate"
        "SAMSUNGELECTRONICSCO.LTD.SamsungSecurity1.2"
        "SAMSUNGELECTRONICSCO.LTD.SamsungScreenRecording"
        "SAMSUNGELECTRONICSCO.LTD.SamsungQuickSearch"
        "SAMSUNGELECTRONICSCO.LTD.SamsungPCCleaner"
        "SAMSUNGELECTRONICSCO.LTD.SamsungCloudBluetoothSync"
        "SAMSUNGELECTRONICSCO.LTD.PCGallery"
        "SAMSUNGELECTRONICSCO.LTD.OnlineSupportSService"
        "4AE8B7C2.BOOKING.COMPARTNERAPPSAMSUNGEDITION"
    )

    $SocialMediaApps = @(
        "5319275A.WhatsAppDesktop"  
        "BytedancePte.Ltd.TikTok"   
        "FACEBOOK.317180B0BB486"    
        "FACEBOOK.FACEBOOK"         
        "Facebook.Instagram*"       
        "*Twitter*"                 
        "*Viber*"
    )

    $StreamingServicesApps = @(
        "AmazonVideo.PrimeVideo"    
        "*Hulu*"
        "*iHeartRadio*"
        "*Netflix*"                 
        "*Plex*"                   
        "*SlingTV*"
        "SpotifyAB.SpotifyMusic"    
        "*TuneInRadio*"
    )

    Write-Title "Remove Windows unneeded Apps (Bloatware)"
    Write-Section "Microsoft Apps"
    Remove-UWPApp -AppxPackages $MSApps
    Write-Section "3rd-party Apps"
    Remove-UWPApp -AppxPackages $ThirdPartyApps
    Write-Section "Manufacturer Apps"
    Remove-UWPApp -AppxPackages $ManufacturerApps
    Write-Section "Social Media Apps"
    Remove-UWPApp -AppxPackages $SocialMediaApps
    Write-Section "Streaming Services Apps"
    Remove-UWPApp -AppxPackages $StreamingServicesApps
}

Remove-BloatwareAppsList

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-CapabilityState.psm1"

function Remove-CapabilitiesList() {
    [CmdletBinding()]
    param (
        [Switch] $Revert
    )

    $DisableCapabilities = [System.Collections.ArrayList] @(
        "App.StepsRecorder*"                
        "Browser.InternetExplorer*"         
        "MathRecognizer*"                   
        "Microsoft.Windows.PowerShell.ISE*" 
        "Microsoft.Windows.WordPad*"        
        "Print.Fax.Scan*"                  
        "Print.Management.Console*"         
    )

    If (Get-AppxPackage -AllUsers -Name "MicrosoftCorporationII.QuickAssist") {
        $DisableCapabilities.Add("App.Support.QuickAssist*")
    }

    $DisableCapabilities.Sort()

    Write-Title "Windows Capabilities Tweaks"
    Write-Section "Uninstall Windows Capabilities from Windows"

    If ($Revert) {
        Write-Status -Types "*", "Capability" -Status "Reverting the tweaks is set to '$Revert'." -Warning
        Set-CapabilityState -State Enabled -Capabilities $DisableCapabilities
    } Else {
        Set-CapabilityState -State Disabled -Capabilities $DisableCapabilities
    }
}

If (!$Revert) {
    Remove-CapabilitiesList 
} Else {
    Remove-CapabilitiesList -Revert
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-ItemVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-UWPApp.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\ui\Show-MessageDialog.psm1"

function Remove-MSEdge() {
    $PathToLMEdgeUpdate = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate"

    Write-Status -Types "@" -Status "Stopping all 'msedge' processes before uninstalling..."
    Get-Process -Name msedge | Stop-Process -PassThru -Force

    If (Test-Path -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge\Application") {
        ForEach ($FullName in (Get-ChildItem -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge*\Application\*\Installer\setup.exe").FullName) {
            Write-Status -Types "@" -Status "Uninstalling MS Edge from $FullName..."
            Start-Process -FilePath $FullName -ArgumentList "--uninstall", "--system-level", "--verbose-logging", "--force-uninstall" -Wait
        }
    } Else {
        Write-Status -Types "?" -Status "Edge folder does not exist anymore..." -Warning
    }

    If (Test-Path -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeCore") {
        ForEach ($FullName in (Get-ChildItem -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeCore\*\Installer\setup.exe").FullName) {
            Write-Status -Types "@" -Status "Uninstalling MS Edge from $FullName..."
            Start-Process -FilePath $FullName -ArgumentList "--uninstall", "--system-level", "--verbose-logging", "--force-uninstall" -Wait
        }
    } Else {
        Write-Status -Types "?" -Status "EdgeCore folder does not exist anymore..." -Warning
    }

    Remove-UWPApp -AppxPackages @("Microsoft.MicrosoftEdge", "Microsoft.MicrosoftEdge.Stable", "Microsoft.MicrosoftEdge.*", "Microsoft.MicrosoftEdgeDevToolsClient")
    Set-ScheduledTaskState -State Disabled -ScheduledTasks @("\MicrosoftEdgeUpdateTaskMachineCore", "\MicrosoftEdgeUpdateTaskMachineUA", "\MicrosoftEdgeUpdateTaskUser*")
    Set-ServiceStartup -State 'Disabled' -Services @("edgeupdate", "edgeupdatem", "MicrosoftEdgeElevationService")

    Write-Status -Types "@" -Status "Preventing Edge from reinstalling..."
    Set-ItemPropertyVerified -Path "$PathToLMEdgeUpdate" -Name "DoNotUpdateToEdgeWithChromium" -Type DWord -Value 1

    Write-Status -Types "@" -Status "Deleting Edge appdata\local folders from current user..."
    Remove-ItemVerified -Path "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftEdge*_*" -Recurse -Force | Out-Host

    Write-Status -Types "@" -Status "Deleting Edge from $env:SystemDrive\Program Files (x86)\Microsoft\..."
    Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Edge" -Recurse -Force | Out-Host

    Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force | Out-Host

    Remove-ItemVerified -Path "$env:SystemDrive\Program Files (x86)\Microsoft\Temp" -Recurse -Force | Out-Host
}

$Ask = "Are you sure you want to remove Microsoft Edge from Windows?`nWill uninstall WebView2 and thus break many PWA (Progressive Web App) applications`n(e.g., Snapchat, Instagram...)`n`nYou can reinstall Edge anytime.`nNote: all users logged in will remain."

switch (Show-Question -Title "Warning" -Message $Ask -BoxIcon "Warning") {
    'Yes' {
        Remove-MSEdge
    }
    'No' {
        Write-Host "Aborting..."
    }
    'Cancel' {
        Write-Host "Aborting..." 
    }
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-ItemVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"

function Remove-OneDrive() {
    
    Write-Host "Kill OneDrive process..."
    taskkill.exe /F /IM "OneDrive.exe"
    taskkill.exe /F /IM "explorer.exe"

    Write-Host "Remove OneDrive."
    if (Test-Path "$env:systemroot\System32\OneDriveSetup.exe") {
        & "$env:systemroot\System32\OneDriveSetup.exe" /uninstall
    }
    if (Test-Path "$env:systemroot\SysWOW64\OneDriveSetup.exe") {
        & "$env:systemroot\SysWOW64\OneDriveSetup.exe" /uninstall
    }

    Write-Host "Removing OneDrive leftovers..."
    Remove-ItemVerified -Recurse -Force -ErrorAction SilentlyContinue "$env:localappdata\Microsoft\OneDrive"
    Remove-ItemVerified -Recurse -Force -ErrorAction SilentlyContinue "$env:programdata\Microsoft OneDrive"
    Remove-ItemVerified -Recurse -Force -ErrorAction SilentlyContinue "$env:systemdrive\OneDriveTemp"
  
    If ((Get-ChildItem "$env:userprofile\OneDrive" -Recurse | Measure-Object).Count -eq 0) {
        Remove-ItemVerified -Recurse -Force -ErrorAction SilentlyContinue "$env:userprofile\OneDrive"
    }

    Write-Host "Disable OneDrive via Group Policies."
    Set-ItemPropertyVerified -Path "HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\OneDrive" "DisableFileSyncNGSC" 1

    Write-Host "Remove Onedrive from explorer sidebar."
    New-PSDrive -PSProvider "Registry" -Root "HKEY_CLASSES_ROOT" -Name "HKCR"
    mkdir -Force "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Set-ItemPropertyVerified -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    mkdir -Force "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Set-ItemPropertyVerified -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" "System.IsPinnedToNameSpaceTree" 0
    Remove-PSDrive "HKCR"

    Write-Host "Removing run hook for new users..."
    reg load "hku\Default" "C:\Users\Default\NTUSER.DAT"
    reg delete "HKEY_USERS\Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f
    reg unload "hku\Default"

    Write-Host "Removing startmenu entry..."
    Remove-ItemVerified -Force -ErrorAction SilentlyContinue "$env:userprofile\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk"

    Write-Host "Removing scheduled task..."
    Get-ScheduledTask -TaskPath '\' -TaskName 'OneDrive*' -ea SilentlyContinue | Unregister-ScheduledTask -Confirm:$false

    Write-Host "Restarting explorer..."
    Start-Process "explorer.exe"

    Write-Host "Waiting for explorer to complete loading..."
    Start-Sleep 5
}

Remove-OneDrive

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-UWPApp.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ServiceStartup.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\ui\Show-MessageDialog.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\utils\Individual-Tweaks.psm1"

function Remove-Xbox() {
    $PathToLMServicesXbgm = "HKLM:\SYSTEM\CurrentControlSet\Services\xbgm"
    $TweakType = "Xbox"

    $XboxServices = @(
        "XblAuthManager"                    
        "XblGameSave"                       
        "XboxGipSvc"                        
        "XboxNetApiSvc"
    )

    $XboxApps = @(
        "Microsoft.GamingApp"              
        "Microsoft.GamingServices"          
        "Microsoft.XboxApp"                 
        "Microsoft.XboxGameCallableUI"
        "Microsoft.XboxGameOverlay"
        "Microsoft.XboxSpeechToTextOverlay"
        "Microsoft.XboxGamingOverlay"       
        "Microsoft.XboxIdentityProvider"    
        "Microsoft.Xbox.TCUI"               
    )

    Write-Status -Types "-", $TweakType -Status "Disabling ALL Xbox Services..."
    Set-ServiceStartup -State 'Disabled' -Services $XboxServices

    Write-Status -Types "-", $TweakType -Status "Wiping Xbox Apps completely from Windows..."
    Remove-UWPApp -AppxPackages $XboxApps

    Write-Status -Types "-", $TweakType -Status "Disabling Xbox Game Monitoring..."
    Set-ItemPropertyVerified -Path "$PathToLMServicesXbgm" -Name "Start" -Type DWord -Value 4

    Disable-XboxGameBarDVRandMode
}

$Ask = "This will remove and/or disable all the Xbox:`n  - Apps;`n  - Services and;`n  - GameBar;`n  - GameDVR.`n`nDo you want to proceed?"

switch (Show-Question -Title "Warning" -Message $Ask -BoxIcon "Warning") {
    'Yes' {
        Remove-Xbox 
    }
    'No' {
        Write-Host "Aborting..."
    }
    'Cancel' {
        Write-Host "Aborting..." 
    }
}

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Set-ItemPropertyVerified.psm1"

function Repair-WindowsSystem() {
    Write-Title "Repair major Windows problems"

    Write-Section "Reset Windows Hosts file"
    $RestoreHosts = "# Copyright (c) 1993-2009 Microsoft Corp.`n#`n# This is a sample HOSTS file used by Microsoft TCP/IP for Windows.`n#`n# This file contains the mappings of IP addresses to host names. Each`n# entry should be kept on an individual line. The IP address should`n# be placed in the first column followed by the corresponding host name.`n# The IP address and the host name should be separated by at least one`n# space.`n#`n# Additionally, comments (such as these) may be inserted on individual`n# lines or following the machine name denoted by a '#' symbol.`n#`n# For example:`n#`n#      102.54.94.97     rhino.acme.com          # source server`n#       38.25.63.10     x.acme.com              # x client host`n`n# localhost name resolution is handled within DNS itself.`n#    127.0.0.1       localhost`n#    ::1             localhost"

    Push-Location -Path "$env:SystemRoot\System32\drivers\etc\"
    Write-Caption "Restoring default hosts file..."
    Write-Output $RestoreHosts > .\hosts
    Pop-Location

    Write-Section "Fix missing Power Plans"
    Write-Caption "Restoring default Power Plans..."
    powercfg -RestoreDefaultSchemes

    Write-Section "Fix MS Store"
    Write-Caption "Running wsreset..."
    Start-Process wsreset -NoNewWindow | Out-Host

    Write-Section "Fix Windows Taskbar"
    Write-Caption "Restoring Windows Taskbar DLL links..."
    Start-Process -FilePath "$env:SystemRoot\System32\Regsvr32.exe" -ArgumentList "/s $env:SystemRoot\System32\msimtf.dll" | Out-Host
    Start-Process -FilePath "$env:SystemRoot\System32\Regsvr32.exe" -ArgumentList "/s $env:SystemRoot\System32\msctf.dll" | Out-Host
    Start-Process -Verb RunAs "$env:SystemRoot\System32\ctfmon.exe" | Out-Host

    Write-Section "Remove 'Test Mode' Watermark"
    Write-Caption "Disabling TestSigning on bcdedit..."
    bcdedit -set TESTSIGNING OFF | Out-Host

    Write-Section "Remove BITS stuck jobs"
    Write-Caption "Removing all BITS transfers..."
    Get-BitsTransfer | Remove-BitsTransfer

    Write-Section "Fix Windows Registry and Image"
    Write-Caption "Running SFC repair (This may take some time)..."
    SFC -ScanNow | Out-Host
    Write-Caption "Running DISM repair (This may take some time)..."
    DISM -Online -CleanUp-Image -RestoreHealth | Out-Host

    Write-Section "Re-register all your apps"
    Write-Caption "Closing Windows Explorer..."
    taskkill /F /IM explorer.exe
    Write-Caption "Re-registering all Windows Apps via AppXManifest.xml ..."
    Set-ItemPropertyVerified -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "EnableXamlStartMenu" -Type Dword -Value 0
    Get-AppxPackage -AllUsers | ForEach-Object {
        Write-Status -Types "@" -Status "Trying to register package: $($_.InstallLocation)"
        Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"
    }
    Write-Caption "Restarting Windows Explorer..."
    Start-Process explorer

    Write-Section "Solving Network problems"
    Write-Caption "Resetting IPv4 and IPv6 addresses..."
    Write-Status -Types "?" -Status "Your internet may fall during the process, please be patient..." -Warning
    ipconfig -Release | Out-Host
    ipconfig -Release6 | Out-Host
    Write-Caption "Renewing IPv4 address..."
    Write-Status -Types "?" -Status "This may take time, please be patient..." -Warning
    ipconfig -Renew *Ethernet* | Out-Host
    Write-Caption "Renewing IPv6 address..."
    ipconfig -Renew6 *Ethernet* | Out-Host

    Write-Caption "Flushing DNS..."
    ipconfig -FlushDns | Out-Host

    Write-Caption "Resetting Winsock..."
    netsh winsock reset | Out-Host
}

Repair-WindowsSystem

Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Get-TempScriptFolder.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Request-FileDownload.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\Title-Templates.psm1"
Import-Module -DisableNameChecking "$PSScriptRoot\..\lib\debloat-helper\Remove-ItemVerified.psm1"

function Use-DebloatSoftware() {
    [CmdletBinding()]
    param (
        [Switch] $Revert
    )

    If (!$Revert) {
        $AdwCleanerDl = "https://downloads.malwarebytes.com/file/adwcleaner"
        [String] $AdwCleanerOutput = (Request-FileDownload -FileURI $AdwCleanerDl -OutputFile "adwcleaner.exe")
        Write-Status -Types "+" -Status "Running MalwareBytes AdwCleaner scanner..."
        Start-Process -FilePath "$AdwCleanerOutput" -ArgumentList "/eula", "/clean", "/noreboot" -Wait
        Remove-ItemVerified $AdwCleanerOutput -Force
    }

    Copy-Item -Path "$PSScriptRoot\..\configs\shutup10" -Destination "$(Get-TempScriptFolder)\downloads" -Recurse -Force
    $ShutUpDl = "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe"
    [String] $ShutUpOutput = Request-FileDownload -FileURI $ShutUpDl -ExtendFolder "shutup10" -OutputFile "OOSU10.exe"
    Push-Location -Path (Split-Path -Path $ShutUpOutput)

    If ($Revert) {
        Write-Status -Types "*" -Status "Running ShutUp10 and REVERTING to default settings..."
        Start-Process -FilePath $ShutUpOutput -ArgumentList "ooshutup10-default.cfg", "/quiet" -Wait 
    } Else {
        Write-Status -Types "+" -Status "Running ShutUp10 and applying Recommended settings..."
        Start-Process -FilePath $ShutUpOutput -ArgumentList "ooshutup10.cfg", "/quiet" -Wait 
    }

    Remove-ItemVerified $ShutUpOutput -Force 
    Pop-Location
}

If (!$Revert) {
    Use-DebloatSoftware 
} Else {
    Use-DebloatSoftware -Revert
}

function Optimize-SSD() {

    fsutil behavior set DisableLastAccess 1
    fsutil behavior set EncryptPagingFile 0
}

Optimize-SSD

$services = @(
    "diagnosticshub.standardcollector.service"     
    "DiagTrack"                                    
    "dmwappushservice"                            
    "lfsvc"                                       
    "MapsBroker"                                   
    "NetTcpPortSharing"                           
    "RemoteAccess"                                 
    "RemoteRegistry"                              
    "SharedAccess"                                 
    "TrkWks"                                      
    "WbioSrvc"                                    
    "WMPNetworkSvc"                               
    "WSearch"                                      
    "XblAuthManager"                              
    "XblGameSave"                                 
    "XboxNetApiSvc"                                
    "XboxGipSvc"                              
    "WerSvc"                                       
    "Spooler"                                      
    "Fax"                                          
    "fhsvc"                                        
    "gupdate"                                     
    "gupdatem"                                     
    "stisvc"                                       
    "AJRouter"                                     
    "MSDTC"                                      
    "WpcMonSvc"                                  
    "PhoneSvc"                                     
    "PcaSvc"                                      
    "WPDBusEnum"                                   
    "LicenseManager"                               
    "seclogon"                                    
    "SysMain"                                      
    "lmhosts"                                     
    "wisvc"                                        
    "FontCache"                                    
    "RetailDemo"                                  
    "ALG"                                          
    "SCardSvr"                                     
    "SCPolicySvc"                                 
    "ScDeviceEnum"                                 
    "MessagingService_34048"                       
    "wlidsvc"                                      
    "EntAppSvc"                                    
    "BthAvctpSvc"                                  
    "Browser"                                      
    "BthAvctpSvc"                                  
    "BDESVC"                                       
    "iphlpsvc"                                        
    "edgeupdate"                                   
    "MicrosoftEdgeElevationService"                
    "edgeupdatem"                                                           
    "SEMgrSvc"                                     
    "PerfHost"                                     
    "BcastDVRUserService_48486de"                  
    "CaptureService_48486de"                       
    "cbdhsvc_48486de"                              
    "BluetoothUserService_48486de"                 
    "DoSvc"                                        
    "RtkBtManServ"                                 
    "QWAVE"                                        
    "SNMPTrap"                                     
    "SECOMNService"                                
    "cbdhsvc_34048"                                
    "autotimesvc"                                  
    "TokenBroker"                                  
    "RmSvc"                                       
    "RtkAudioUniversalService"                    
    "SensorDataService"                            
    "EventLog"                                   
    "tzautoupdate"                                 
    "SynTPEnhService"                              
    "RasMan"                                       
    "PenService_34048"                                                              
    "HPAppHelperCap"                                
    "HPDiagsCap"                                    
    "HPNetworkCap"                                  
    "HPSysInfoCap"                                  
    "HpTouchpointAnalyticsService"                  
    "HvHost"                                       
    "vmickvpexchange"                               
    "vmicguestinterface"                            
    "vmicshutdown"                                  
    "vmicheartbeat"                                 
    "vmicvmsession"                                 
    "vmicrdv"                                       
    "vmictimesync"                                 
    "SupportAssistAgent"                           
    "DellUpService"                                 
    "DataVault"                                     
    "DellCustomerConnect"                          
    "Dell.Foundation.Agent"                        
    "nosGetPlusHelper"                              
    "LSCNotify"                                     
    "LnvAgent"                                      
    "Lenovo.Modern.ImController.PluginHost.CompanionApp" 
    "Lenovo.Modern.ImController.PluginHost.Device" 
    "Lenovo.Modern.ImController"                    
    "LenovoUtility"                                 

    Out-File -FilePath  ".\log.txt" -Append
)

foreach ($service in $services) {
    Get-Service -Name $service | Stop-Service -Force | Out-File -FilePath  ".\log.txt" -Append
    Get-Service -Name $service | Set-Service -StartupType Disabled | Out-File -FilePath  ".\log.txt" -Append
    Write-Output "Trying to disable $service" | Out-File -FilePath  ".\log.txt" -Append
    Write-Output "Trying to Stop $service" | Out-File -FilePath  ".\log.txt" -Append
}

$acer = Get-Service | Where-Object {$_.DisplayName -like '*Acer*'}
foreach ($acer in $acer) {
    Get-Service -Name $acer | Stop-Service -Force 
    Get-Service -Name $acer | Set-Service -StartupType Disabled 
    The follow acer service is being stopped Stop-Service $acer 
    The follow acer service is being disabled Disable-Service $acer 
}

$sam = Get-Service | Where-Object {$_.DisplayName -like '*Samsung*'}
foreach ($sam in $sam) {
    Get-Service -Name $sam | Stop-Service -Force 
    Get-Service -Name $sam | Set-Service -StartupType Disabled 
    The follow acer service is being stopped Stop-Service $sam
    The follow acer service is being disabled Disable-Service $sam
    Out-File -FilePath  ".\log.txt"
}

$msi = Get-Service | Where-Object {$_.DisplayName -like '*msi*'}
foreach ($msi in $msi) {
    Get-Service -Name $msi | Stop-Service -Force 
    Get-Service -Name $msi | Set-Service -StartupType Disabled 
    The follow acer service is being stopped Stop-Service $msi
    The follow acer service is being disabled Disable-Service $msi
    Out-File -FilePath  ".\log.txt"
}

$Huawei = Get-Service | Where-Object {$_.DisplayName -like '*Huawei*'}
foreach ($Huawei in $Huawei) {
    Get-Service -Name $Huawei | Stop-Service -Force 
    Get-Service -Name $Huawei | Set-Service -StartupType Disabled 
    The follow acer service is being stopped Stop-Service $Huawei
    The follow acer service is being disabled Disable-Service $Huawei 
}

$services = @(
    "diagnosticshub.standardcollector.service" 
    "DiagTrack"                                
    "dmwappushservice"                         
    "lfsvc"                                    
    "MapsBroker"                               
    "NetTcpPortSharing"                        
    "RemoteAccess"                             
    "RemoteRegistry"                           
    "SharedAccess"                             
    "TrkWks"                                   
    "WbioSrvc"                                 
    "WMPNetworkSvc"                            
    "XblAuthManager"                           
    "XblGameSave"                              
    "XboxNetApiSvc"                            
    "ndu"                                      
)

foreach ($service in $services) {
    Write-Output "Trying to disable $service"
    Get-Service -Name $service | Set-Service -StartupType Disabled
}

$name = Read-Host -Prompt 'Enter new workstation name'
Rename-Computer -NewName $name

New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ -Name NamingTemplates -Force
New-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\NamingTemplates -Name "ShortcutNameTemplate" -PropertyType "String" -Value '%s.lnk'

$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
Set-ItemProperty $key Hidden 1
Set-ItemProperty $key HideFileExt 0
Stop-Process -processname explorer

Get-AppxPackage *3dbuilder* | Remove-AppxPackage
Get-AppxPackage *windowsalarms* | Remove-AppxPackage
Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage
Get-AppxPackage *windowscamera* | Remove-AppxPackage
Get-AppxPackage *officehub* | Remove-AppxPackage
Get-AppxPackage *skypeapp* | Remove-AppxPackage
Get-AppxPackage *getstarted* | Remove-AppxPackage
Get-AppxPackage *zunemusic* | Remove-AppxPackage
Get-AppxPackage *windowsmaps* | Remove-AppxPackage
Get-AppxPackage *solitairecollection* | Remove-AppxPackage
Get-AppxPackage *bingfinance* | Remove-AppxPackage
Get-AppxPackage *zunevideo* | Remove-AppxPackage
Get-AppxPackage *bingnews* | Remove-AppxPackage
Get-AppxPackage *onenote* | Remove-AppxPackage

Get-AppxPackage *windowsphone* | Remove-AppxPackage
Get-AppxPackage *photos* | Remove-AppxPackage
Get-AppxPackage *windowsstore* | Remove-AppxPackage
Get-AppxPackage *bingsports* | Remove-AppxPackage
Get-AppxPackage *soundrecorder* | Remove-AppxPackage
Get-AppxPackage *bingweather* | Remove-AppxPackage
Get-AppxPackage *xboxapp* | Remove-AppxPackage

Get-AppxPackage *FarmVille2CountryEscape* | Remove-AppxPackage
Get-AppxPackage *Microsoft.XboxIdentityProvider* | Remove-AppxPackage
Get-AppxPackage *king.com.CandyCrushSodaSaga* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Advertising.Xaml* | Remove-AppxPackage
Get-AppxPackage *Microsoft.WindowsFeedbackHub* | Remove-AppxPackage
Get-AppxPackage *Microsoft.StorePurchaseApp* | Remove-AppxPackage
Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage
Get-AppxPackage *PandoraMediaInc* | Remove-AppxPackage
Get-AppxPackage *Drawboard.DrawboardPDF* | Remove-AppxPackage
Get-AppxPackage *Twitter* | Remove-AppxPackage
Get-AppxPackage *Candy* | Remove-AppxPackage
Get-AppxPackage *FarmVille* | Remove-AppxPackage
Get-AppxPackage *One* | Remove-AppxPackage

Get-AppxPackage *Microsoft.NetworkSpeedTest* | Remove-AppxPackage
Get-AppxPackage *office.sway* | Remove-AppxPackage
Get-AppxPackage *xbox* | Remove-AppxPackage
Get-AppxPackage *netflix* | Remove-AppxPackage
Get-AppxPackage *stickynotes* | Remove-AppxPackage
Get-AppxPackage *print3d* | Remove-AppxPackage
Get-AppxPackage *3dviewer* | Remove-AppxPackage
Get-AppxPackage *mixedreality* | Remove-AppxPackage
Get-AppxPackage *wallet* | Remove-AppxPackage

Get-AppXProvisionedPackage -Online | Remove-AppxProvisionedPackage -Online

write-host Stopping OneDrive
taskkill /f /im OneDrive.exe
timeout /t 3 /nobreak

Write-Host Uninstalling OneDrive
& $env:SystemRoot\SysWOW64\OneDriveSetup.exe /uninstall
timeout /t 3 /nobreak

Write-Host Removing OneDrive from the Explorer Side Panel
REG DELETE "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
REG DELETE "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f

Set-NetConnectionProfile -NetworkCategory Private

Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -name "UserAuthentication" -Value 1

tzutil.exe /s "Central Standard Time"

New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\ -Name WindowsUpdate -Force
New-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate -Name "ExcludeWUDriversInQualityUpdate" -PropertyType "DWord" -Value '1'

Set-Service SysMain -StartupType Disabled
Stop-Service SysMain

Set-ItemProperty -path "HKCU:Control Panel\Desktop" -Name WallPaper -value ""
RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters ,1 ,True

New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\" -Name "Windows Search" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -PropertyType "DWord" -Value '0'

Get-WindowsCapability -Online | ? {$_.Name -like "*InternetExplorer*"} | Remove-WindowsCapability -Online

Get-WindowsCapability -Online | ? {$_.Name -like "*Hello.Face*" -and $_.State -eq 'Installed'} | Remove-WindowsCapability -Online
Get-WindowsCapability -Online | ? {$_.Name -like "*Handwriting*" -and $_.State -eq 'Installed'} | Remove-WindowsCapability -Online

$NameSpaceKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace'
$HideIconsKey = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideMyComputerIcons'

If (!(Test-Path $HideIconsKey)) {mkdir $HideIconsKey -Force}
$splat = @{
    'Path'  = $HideIconsKey
    'Name'  = ''
    'Value' = 1
}

(Get-ChildItem $NameSpaceKey).PSChildName -like "{*}" | ForEach-Object {
    $splat['Name'] = $_
    Set-ItemProperty @splat
}
pause
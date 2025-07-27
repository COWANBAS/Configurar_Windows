:: Desabilita o gerenciamento de energia de dispositivos WMI.
PowerShell -Command "Get-WmiObject MSPower_DeviceEnable -Namespace root\wmi | ForEach-Object { $_.enable = $false; $_.psbase.put(); }"

:: Desabilita o serviço de Diagnóstico e Telemetria (DiagTrack).
PowerShell -Command "Get-Service DiagTrack | Set-Service -StartupType Disabled"

:: Desabilita o serviço de mensagens push de WAP (dmwappushservice).
PowerShell -Command "Get-Service dmwappushservice | Set-Service -StartupType Disabled"

:: Desabilita o serviço de coletor padrão do Hub de Diagnóstico.
PowerShell -Command "Get-Service diagnosticshub.standardcollector.service | Set-Service -StartupType Disabled"

:: Desabilita o serviço de Política de Diagnóstico (DPS).
PowerShell -Command "Get-Service DPS | Set-Service -StartupType Disabled"

:: Desabilita o serviço de Registro Remoto.
PowerShell -Command "Get-Service RemoteRegistry | Set-Service -StartupType Disabled"

:: Desabilita o serviço de Cliente de Rastreamento de Link Distribuído (TrkWks).
PowerShell -Command "Get-Service TrkWks | Set-Service -StartupType Disabled"

:: Desabilita o serviço Compartilhamento de Rede do Windows Media Player (WMPNetworkSvc).
PowerShell -Command "Get-Service WMPNetworkSvc | Set-Service -StartupType Disabled"

:: Desabilita o serviço de Pesquisa do Windows (WSearch).
PowerShell -Command "Get-Service WSearch | Set-Service -StartupType Disabled"

:: Desabilita o SuperFetch/PreFetch (SysMain).
PowerShell -Command "Get-Service SysMain | Set-Service -StartupType Disabled"

:: Desabilita o recurso opcional Internet Explorer.
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "Internet-Explorer-Optional-amd64"

:: Desabilita o recurso opcional de Reprodução de Mídia.
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "MediaPlayback"

:: Desabilita o recurso opcional Windows Media Player.
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "WindowsMediaPlayer"

:: Desabilita o recurso opcional Cliente de Pastas de Trabalho.
PowerShell -Command Disable-WindowsOptionalFeature -Online -NoRestart -FeatureName "WorkFolders-Client"

:: Remove o aplicativo 3D Builder provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.3DBuilder | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Bing Finanças provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.BingFinance | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Bing Notícias provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.BingNews | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Introdução provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.Getstarted | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Microsoft Office Hub provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.MicrosoftOfficeHub | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Microsoft Solitaire Collection provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.MicrosoftSolitaireCollection | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Microsoft OneNote provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.Office.OneNote | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Skype provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.SkypeApp | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Windows Phone provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.WindowsPhone | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Xbox provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.XboxApp | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Zune Music (Groove Music) provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.ZuneMusic | Remove-AppxProvisionedPackage -Online"

:: Remove o aplicativo Zune Video (Filmes e TV) provisionado.
PowerShell -Command "Get-AppxProvisionedPackage -Online | Where-Object DisplayName -eq Microsoft.ZuneVideo | Remove-AppxProvisionedPackage -Online"

:: Remove todos os pacotes AppX da Microsoft instalados.
PowerShell -Command "Get-AppxPackage *Microsoft* | Remove-AppxPackage"

:: Remove todos os pacotes AppX provisionados (para novos usuários).
PowerShell -Command "Get-AppXProvisionedPackage -online | Remove-AppxProvisionedPackage -online"

:: Remove todos os pacotes AppX instalados para o usuário atual.
PowerShell -Command "Get-AppXPackage | Remove-AppxPackage"

:: Remove todos os pacotes AppX para o usuário atual (redundante com o anterior).
PowerShell -Command "Get-AppXPackage -User | Remove-AppxPackage"

:: Remove todos os pacotes AppX para todos os usuários.
PowerShell -Command "Get-AppxPackage -AllUsers | Remove-AppxPackage"

:: Desabilita tarefa de sessão do Windows Shell.
SCHTASKS /Change /TN "\Microsoft\Windows\WS\WSTask" /DISABLE

:: Desabilita manutenção de Pastas de Trabalho.
SCHTASKS /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /DISABLE

:: Desabilita sincronização de Pastas de Trabalho no logon.
SCHTASKS /Change /TN "\Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /DISABLE

:: Desabilita validação de hash WIM (Windows Image Format).
SCHTASKS /Change /TN "\Microsoft\Windows\WOF\WIM-Hash-Validation" /DISABLE

:: Desabilita gerenciamento de hash WIM.
SCHTASKS /Change /TN "\Microsoft\Windows\WOF\WIM-Hash-Management" /DISABLE

:: Desabilita tarefa de serviço de atualização (sih).
SCHTASKS /Change /TN "\Microsoft\Windows\WindowsUpdate\sih" /DISABLE

:: Desabilita tarefa de Plataforma de Filtro do Windows (BFE).
SCHTASKS /Change /TN "\Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /DISABLE

:: Desabilita envio de relatórios de erro do Windows.
SCHTASKS /Change /TN "\Microsoft\Windows\Windows Error Reporting\QueueReporting" /DISABLE

:: Desabilita tarefa de host de resolução de diagnóstico (WDI).
SCHTASKS /Change /TN "\Microsoft\Windows\WDI\ResolutionHost" /DISABLE

:: Desabilita agendamento de verificação do Update Orchestrator.
SCHTASKS /Change /TN "\Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /DISABLE

:: Desabilita tarefa de avaliação de swap do SysMain.
SCHTASKS /Change /TN "\Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /DISABLE

:: Desabilita sincronização de banco de dados de prioridade do SysMain.
SCHTASKS /Change /TN "\Microsoft\Windows\Sysmain\ResPriStaticDbSync" /DISABLE

:: Desabilita reinício de serviço da Plataforma de Proteção de Software (rede).
SCHTASKS /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskNetwork" /DISABLE

:: Desabilita reinício de serviço da Plataforma de Proteção de Software (logon).
SCHTASKS /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTaskLogon" /DISABLE

:: Desabilita reinício de serviço da Plataforma de Proteção de Software.
SCHTASKS /Change /TN "\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask" /DISABLE

:: Desabilita manutenção automática do Indexador do Shell.
SCHTASKS /Change /TN "\Microsoft\Windows\Shell\IndexerAutomaticMaintenance" /DISABLE

:: Desabilita tarefa de mudança de estado de rede da Sincronização de Configurações.
SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\NetworkStateChangeTask" /DISABLE

:: Desabilita tarefa de upload em segundo plano da Sincronização de Configurações.
SCHTASKS /Change /TN "\Microsoft\Windows\SettingSync\BackgroundUploadTask" /DISABLE

:: Desabilita tarefa de Assistência Remota.
SCHTASKS /Change /TN "\Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /DISABLE

:: Desabilita tarefas de telemetria de Programa de Experiência do Usuário (PI).
SCHTASKS /Change /TN "\Microsoft\Windows\PI\Sqm-Tasks" /DISABLE

:: Desabilita coleta de informações de rede.
SCHTASKS /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /DISABLE

:: Desabilita tarefa de atualização de Mapas.
SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /DISABLE

:: Desabilita tarefa de notificação de Mapas.
SCHTASKS /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /DISABLE

:: Desabilita avaliação de desempenho do sistema (WinSAT).
SCHTASKS /Change /TN "\Microsoft\Windows\Maintenance\WinSAT" /DISABLE

:: Desabilita manutenção do Histórico de Arquivos.
SCHTASKS /Change /TN "\Microsoft\Windows\FileHistory\File History (maintenance mode)" /DISABLE

:: Desabilita sincronização de definição de propriedade da Classificação de Arquivos.
SCHTASKS /Change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /DISABLE

:: Desabilita sincronização de definição de propriedade da Classificação de Arquivos (duplicado).
SCHTASKS /Change /TN "\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync" /DISABLE

:: Desabilita cliente de feedback (Siuf\DmClientOnScenarioDownload).
SCHTASKS /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /DISABLE

:: Desabilita cliente de feedback (Siuf\DmClient).
SCHTASKS /Change /TN "\Microsoft\Windows\Feedback\Siuf\DmClient" /DISABLE

:: Desabilita coletor de dados de diagnóstico de disco.
SCHTASKS /Change /TN "\Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /DISABLE

:: Desabilita programa de aprimoramento de experiência do usuário (UsbCeip).
SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /DISABLE

:: Desabilita programa de aprimoramento de experiência do usuário (KernelCeipTask).
SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE

:: Desabilita programa de aprimoramento de experiência do usuário (Consolidator).
SCHTASKS /Change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE

:: Desabilita tarefa de criação de objeto do CloudExperienceHost.
SCHTASKS /Change /TN "\Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /DISABLE

:: Desabilita tarefa de usuário de Certificado (roaming).
SCHTASKS /Change /TN "\Microsoft\Windows\CertificateServicesClient\UserTask-Roam" /DISABLE

:: Desabilita tarefa de proxy Autochk.
SCHTASKS /Change /TN "\Microsoft\Windows\Autochk\Proxy" /DISABLE

:: Desabilita limpeza de aplicativos pré-estagiados do AppxDeploymentClient.
SCHTASKS /Change /TN "\Microsoft\Windows\AppxDeploymentClient\Pre-staged app cleanup" /DISABLE

:: Desabilita tarefa de aplicativo de inicialização da Experiência do Aplicativo.
SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\StartupAppTask" /DISABLE

:: Desabilita atualizador de dados de programa da Experiência do Aplicativo.
SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\ProgramDataUpdater" /DISABLE

:: Desabilita avaliador de compatibilidade da Microsoft.
SCHTASKS /Change /TN "\Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /DISABLE

:: Desabilita tarefa SmartScreen específica do AppID.
SCHTASKS /Change /TN "\Microsoft\Windows\AppID\SmartScreenSpecific" /DISABLE

:: Desabilita telemetria do Office no logon.
SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetryAgentLogOn" /DISABLE

:: Desabilita telemetria de fallback do Office.
SCHTASKS /Change /TN "\Microsoft\Office\OfficeTelemetryAgentFallBack" /DISABLE

:: Desabilita monitoramento de telemetria da Nvidia.
SCHTASKS /Change /TN "\NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable

:: Desabilita relatório de telemetria da Nvidia.
SCHTASKS /Change /TN "\NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable

:: Desabilita relatório de telemetria da Nvidia no logon.
SCHTASKS /Change /TN "\NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8}" /Disable

:: Desabilita avaliador de compatibilidade da Microsoft (duplicado).
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable

:: Desabilita atualizador de dados de programa (duplicado).
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable

:: Desabilita tarefa de aplicativo de inicialização (duplicado).
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable

:: Desabilita consolidador do Programa de Experiência do Cliente (duplicado).
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable

:: Desabilita tarefa CEIP do kernel (duplicado).
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable

:: Desabilita CEIP USB (duplicado).
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

:: Desabilita uploader do Programa de Experiência do Cliente.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable

:: Desabilita upload de Segurança Familiar do Shell.
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable

:: Desabilita telemetria do Office no logon (duplicado).
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable

:: Desabilita telemetria de fallback do Office (duplicado).
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable

:: Desabilita batimento cardíaco da assinatura do Office 15.
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable

:: Desabilita notificação de fim de suporte (EOSNotify).
schtasks /Change /DISABLE /TN "Microsoft\Windows\Setup\EOSNotify"

:: Desabilita notificação de fim de suporte (EOSNotify2).
schtasks /Change /DISABLE /TN "Microsoft\Windows\Setup\EOSNotify2"

:: Exclui tarefa de notificação de fim de suporte (EOSNotify).
schtasks /Delete /F /TN "Microsoft\Windows\Setup\EOSNotify"

:: Exclui tarefa de notificação de fim de suporte (EOSNotify2).
schtasks /Delete /F /TN "Microsoft\Windows\Setup\EOSNotify2"

:: Desabilita notificação de fim de suporte (Notify1).
schtasks /Change /DISABLE /TN "Microsoft\Windows\End Of Support\Notify1"

:: Desabilita notificação de fim de suporte (Notify2).
schtasks /Change /DISABLE /TN "Microsoft\Windows\End Of Support\Notify2"

:: Exclui tarefa de notificação de fim de suporte (Notify1).
schtasks /Delete /F /TN "Microsoft\Windows\End Of Support\Notify1"

:: Exclui tarefa de notificação de fim de suporte (Notify2).
schtasks /Delete /F /TN "Microsoft\Windows\End Of Support\Notify2"

:: Desabilita tarefa de telemetria de instalação (SetupSQMTask).
schtasks /Change /DISABLE /TN "Microsoft\Windows\SetupSQMTask"

:: Desabilita telemetria Bluetooth (BthSQM).
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM"

:: Desabilita consolidador de telemetria CEIP.
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"

:: Desabilita tarefa CEIP do kernel.
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"

:: Desabilita tarefa de telemetria geral (TelTask).
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\TelTask"

:: Desabilita telemetria USB (UsbCeip).
schtasks /Change /DISABLE /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"

:: Desabilita agente de compatibilidade de aplicativos (AitAgent).
schtasks /Change /DISABLE /TN "Microsoft\Windows\Application Experience\AitAgent"

:: Desabilita avaliador de compatibilidade da Microsoft.
schtasks /Change /DISABLE /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"

:: Desabilita atualizador de dados de programa.
schtasks /Change /DISABLE /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater"

:: Desabilita coletor de dados de configuração em segundo plano.
schtasks /Change /DISABLE /TN "Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"

:: Exclui tarefa de telemetria de instalação (SetupSQMTask).
schtasks /Delete /F /TN "Microsoft\Windows\SetupSQMTask"

:: Exclui telemetria Bluetooth (BthSQM).
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM"

:: Exclui consolidador de telemetria CEIP.
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator"

:: Exclui tarefa CEIP do kernel.
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask"

:: Exclui tarefa de telemetria geral (TelTask).
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\TelTask"

:: Exclui telemetria USB (UsbCeip).
schtasks /Delete /F /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip"

:: Exclui avaliador de compatibilidade da Microsoft.
schtasks /Delete /F /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser"

:: Exclui atualizador de dados de programa.
schtasks /Delete /F /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater"

:: Exclui agente de compatibilidade de aplicativos (AitAgent).
schtasks /Delete /F /TN "Microsoft\Windows\Application Experience\AitAgent"

:: Exclui coletor de dados de configuração em segundo plano.
schtasks /Delete /F /TN "Microsoft\Windows\PerfTrack\BackgroundConfigSurveyor"

:: Desabilita atualização de política MDM do ExploitGuard.
schtasks /Change /TN "Microsoft\Windows\ExploitGuard\ExploitGuard MDM policy Refresh" /Disable

:: Desabilita manutenção de cache do Windows Defender.
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance" /Disable

:: Desabilita limpeza do Windows Defender.
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Cleanup" /Disable

:: Desabilita varredura agendada do Windows Defender.
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan" /Disable

:: Desabilita verificação do Windows Defender.
schtasks /Change /TN "Microsoft\Windows\Windows Defender\Windows Defender Verification" /Disable

:: Desabilita atualização automática de aplicativos do Windows Update.
SCHTASKS /Change /TN "\Microsoft\Windows\WindowsUpdate\Automatic App Update" /DISABLE

:: Desabilita início agendado do Windows Update.
SCHTASKS /Change /TN "\Microsoft\Windows\WindowsUpdate\Scheduled Start" /DISABLE

:: Desabilita tarefa de serviço de atualização (sih).
SCHTASKS /Change /TN "\Microsoft\Windows\WindowsUpdate\sih" /DISABLE

:: Desabilita tarefa de serviço de atualização no boot (sihboot).
SCHTASKS /Change /TN "\Microsoft\Windows\WindowsUpdate\sihboot" /DISABLE

:: Desabilita assistente de atualização do Update Orchestrator.
SCHTASKS /Change /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateAssistant" /DISABLE

:: Desabilita execução de calendário do assistente de atualização.
SCHTASKS /Change /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantCalendarRun" /DISABLE

:: Desabilita execução de despertar do assistente de atualização.
SCHTASKS /Change /TN "\Microsoft\Windows\UpdateOrchestrator\UpdateAssistantWakeupRun" /DISABLE

:: Desabilita sincronização CDS do serviço WLAN.
schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable

:: Desabilita tarefa Wi-Fi do WCM.
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable

:: Desabilita tarefa Wi-Fi do NlaSvc.
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable

:: Desabilita tarefa DUSM.
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable

:: Desabilita provedor de impressão educacional.
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable

:: Desabilita tarefa de limpeza de impressora.
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable

:: Desabilita varredura por atualizações do InstallService.
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdates" /Disable

:: Desabilita varredura por atualizações como usuário do InstallService.
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /Disable

:: Desabilita tentativa inteligente do InstallService.
schtasks /Change /TN "Microsoft\Windows\InstallService\SmartRetry" /Disable

:: Desabilita despertar e continuar atualizações do InstallService.
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" /Disable

:: Desabilita despertar e escanear por atualizações do InstallService.
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndScanForUpdates" /Disable

:: Desabilita relatório de políticas do Update Orchestrator.
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Report policies" /Disable

:: Desabilita varredura agendada do Update Orchestrator.
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable

:: Desabilita varredura agendada estática do Update Orchestrator.
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" /Disable

:: Desabilita tarefa de modelo de atualização do Update Orchestrator.
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" /Disable

:: Desabilita UX Broker do USO.
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /Disable

:: Desabilita remediação do WaaSMedic.
schtasks /Change /TN "Microsoft\Windows\WaaSMedic\PerformRemediation" /Disable

:: Desabilita início agendado do Windows Update.
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable

:: Exclui tarefa AMD Install Launcher.
schtasks /DELETE /TN "AMDInstallLauncher" /f

:: Exclui tarefa AMD Link Update.
schtasks /DELETE /TN "AMDLinkUpdate" /f

:: Exclui tarefa AMDRyzenMasterSDKTask.
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f

:: Exclui tarefa Driver Easy Scheduled Scan.
schtasks /DELETE /TN "Driver Easy Scheduled Scan" /f

:: Exclui tarefa ModifyLinkUpdate.
schtasks /DELETE /TN "ModifyLinkUpdate" /f

:: Exclui tarefa SoftMakerUpdater.
schtasks /DELETE /TN "SoftMakerUpdater" /f

:: Exclui tarefa StartCN.
schtasks /DELETE /TN "StartCN" /f

:: Exclui tarefa StartDVR.
schtasks /DELETE /TN "StartDVR" /f

:: Desabilita avaliador de compatibilidade da Microsoft.
echo Desabilita avaliador de compatibilidade da Microsoft.
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable

:: Desabilita tarefa de patch do banco de dados PCA (Application Experience).
echo Desabilita tarefa de patch do banco de dados PCA.
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable

:: Desabilita atualizador de dados de programa.
echo Desabilita atualizador de dados de programa.
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable

:: Desabilita tarefa de aplicativo de inicialização.
echo Desabilita tarefa de aplicativo de inicialização.
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable

:: Desabilita tarefa de proxy Autochk.
echo Desabilita tarefa de proxy Autochk.
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable

:: Desabilita consolidador do Programa de Experiência do Cliente.
echo Desabilita consolidador CEIP.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable

:: Desabilita telemetria USB (CEIP).
echo Desabilita telemetria USB CEIP.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

:: Desabilita desfragmentação agendada.
echo Desabilita desfragmentação agendada.
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable

:: Desabilita tarefa de informações do dispositivo.
echo Desabilita tarefa de info do dispositivo.
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable

:: Desabilita tarefa de informações do usuário do dispositivo.
echo Desabilita tarefa de info do usuário do dispositivo.
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable

:: Desabilita scanner de solução de problemas recomendada.
echo Desabilita scanner de solução de problemas.
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable

:: Desabilita diagnóstico agendado.
echo Desabilita diagnóstico agendado.
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable

:: Desabilita limpeza silenciosa de disco.
echo Desabilita limpeza de disco silenciosa.
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable

:: Desabilita coletor de dados de diagnóstico de disco.
echo Desabilita coletor de diagnóstico de disco.
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable

:: Desabilita diagnósticos de pegada de disco.
echo Desabilita diagnósticos de pegada de disco.
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable

:: Desabilita senso de armazenamento de pegada de disco.
echo Desabilita senso de armazenamento.
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable

:: Desabilita tarefa DUSM (Data Usage).
echo Desabilita tarefa DUSM.
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable

:: Desabilita tarefa de manutenção MDM (Enterprise Management).
echo Desabilita manutenção MDM.
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable

:: Desabilita cliente de telemetria de feedback.
echo Desabilita cliente de feedback.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable

:: Desabilita cliente de telemetria de feedback em download de cenário.
echo Desabilita cliente de feedback em download.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable

:: Desabilita modo de manutenção do Histórico de Arquivos.
echo Desabilita manutenção Histórico de Arquivos.
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable

:: Desabilita reconciliação de recursos do Flighting (configuração de recursos).
echo Desabilita reconciliação de recursos Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable

:: Desabilita descarregamento de dados de uso do Flighting.
echo Desabilita descarregamento dados de uso Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable

:: Desabilita relatório de dados de uso do Flighting.
echo Desabilita relatório dados de uso Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable

:: Desabilita atualização de cache OneSettings do Flighting.
echo Desabilita atualização cache OneSettings Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable

:: Desabilita sincronização de dados de usuário local (entrada).
echo Desabilita sincronização dados usuário local.
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable

:: Desabilita sincronização de dados do mouse (entrada).
echo Desabilita sincronização dados do mouse.
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable

:: Desabilita sincronização de dados da caneta (entrada).
echo Desabilita sincronização dados da caneta.
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable

:: Desabilita sincronização de dados do touchpad (entrada).
echo Desabilita sincronização dados do touchpad.
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable

:: Desabilita sincronização de configurações de idioma.
echo Desabilita sincronização de idioma.
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable

:: Desabilita instalação de componentes de idioma.
echo Desabilita instalação de idioma.
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable

:: Desabilita reconciliação de recursos de idioma.
echo Desabilita reconciliação de idioma.
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable

:: Desabilita desinstalação de componentes de idioma.
echo Desabilita desinstalação de idioma.
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable

:: Desabilita troca de licença temporária assinada.
echo Desabilita troca de licença temp.
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable

:: Desabilita troca de licença temporária assinada (duplicado).
echo Desabilita troca de licença temp (duplicado).
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable

:: Desabilita provisionamento de celular (Gerenciamento).
echo Desabilita provisionamento de celular.
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable

:: Desabilita provisionamento no logon (Gerenciamento).
echo Desabilita provisionamento no logon.
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable

:: Desabilita avaliação de desempenho do sistema (WinSAT).
echo Desabilita avaliação de desempenho (WinSAT).
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable

:: Desabilita tarefa de notificação de Mapas.
echo Desabilita notificação de Mapas.
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable

:: Desabilita tarefa de atualização de Mapas.
echo Desabilita atualização de Mapas.
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable

:: Desabilita parser de metadados de contas de Banda Larga Móvel.
echo Desabilita parser de banda larga móvel.
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable

:: Desabilita remoção de pacote de idioma (MUI).
echo Desabilita remoção de pacote de idioma.
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable

:: Desabilita coleta de informações de rede.
echo Desabilita coleta de info de rede.
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable

:: Desabilita tarefas de telemetria de Programa de Experiência do Usuário (PI).
echo Desabilita telemetria PI.
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable

:: Desabilita análise do sistema para diagnóstico de eficiência energética.
echo Desabilita análise de eficiência energética.
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable

:: Desabilita registro de PushToInstall.
echo Desabilita registro PushToInstall.
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable

:: Desabilita Mobility Manager do RAS.
echo Desabilita Mobility Manager do RAS.
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable

:: Desabilita verificação do Ambiente de Recuperação do Windows (WinRE).
echo Desabilita verificação WinRE.
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable

:: Desabilita tarefa de Assistência Remota.
echo Desabilita tarefa de Assistência Remota.
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable

:: Desabilita limpeza de conteúdo offline de demonstração de varejo.
echo Desabilita limpeza de demonstração.
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable

:: Desabilita limpeza de componentes de serviço.
echo Desabilita limpeza de componentes.
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable

:: Desabilita tarefa de mudança de estado de rede da Sincronização de Configurações.
echo Desabilita mudança de estado de rede (Settings Sync).
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable

:: Desabilita tarefa de limpeza da Instalação.
echo Desabilita limpeza da Instalação.
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable

:: Desabilita tarefa de limpeza de instantâneo da Instalação.
echo Desabilita limpeza de instantâneo da Instalação.
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable

:: Desabilita tarefa do Agente SpacePort.
echo Desabilita Agente SpacePort.
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable

:: Desabilita tarefa do Gerenciador SpacePort.
echo Desabilita Gerenciador SpacePort.
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable

:: Desabilita tarefa de download de modelo de fala.
echo Desabilita download de modelo de fala.
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable

:: Desabilita inicialização de Gerenciamento de Camadas de Armazenamento.
echo Desabilita inicialização de Gerenciamento de Armazenamento.
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable

:: Desabilita sincronização de banco de dados de prioridade do SysMain.
echo Desabilita sincronização de banco de dados SysMain.
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable

:: Desabilita tarefa de avaliação de swap do SysMain.
echo Desabilita avaliação de swap SysMain.
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable

:: Desabilita tarefa interativa do Gerenciador de Tarefas.
echo Desabilita tarefa interativa do Gerenciador.
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable

:: Desabilita forçar sincronização de tempo.
echo Desabilita forçar sincronização de tempo.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable

:: Desabilita sincronização de tempo.
echo Desabilita sincronização de tempo.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable

:: Desabilita sincronização de fuso horário.
echo Desabilita sincronização de fuso horário.
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable

:: Desabilita recuperação de certificado HAS do TPM.
echo Desabilita recuperação de certificado TPM.
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable

:: Desabilita manutenção do TPM.
echo Desabilita manutenção do TPM.
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable

:: Desabilita configuração do host UPnP.
echo Desabilita configuração do host UPnP.
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable

:: Desabilita tarefa de upload de Hive do Perfil de Usuário.
echo Desabilita upload de Hive do Perfil de Usuário.
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable

:: Desabilita host de resolução WDI.
echo Desabilita host de resolução WDI.
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable

:: Desabilita alteração de tipo de início de serviço BFE (WFP).
echo Desabilita alteração de serviço BFE.
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable

:: Desabilita gerenciamento de hash WIM.
echo Desabilita gerenciamento de hash WIM.
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable

:: Desabilita validação de hash WIM.
echo Desabilita validação de hash WIM.
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable

:: Desabilita sincronização de logon de Pastas de Trabalho.
echo Desabilita sincronização de logon de Pastas de Trabalho.
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable

:: Desabilita manutenção de Pastas de Trabalho.
echo Desabilita manutenção de Pastas de Trabalho.
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable

:: Desabilita junção automática de dispositivo no Workplace Join.
echo Desabilita junção automática de dispositivo.
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable

:: Desabilita tarefa de notificação do serviço WWAN.
echo Desabilita notificação WWAN.
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable

:: Desabilita descoberta OOBE do serviço WWAN.
echo Desabilita descoberta OOBE WWAN.
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable

:: Desabilita tarefa de salvamento de jogo Xbox Live.
echo Desabilita salvamento de jogo Xbox Live.
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable

:: Exclui tarefa AMD Install Launcher.
echo Exclui AMD Install Launcher.
schtasks /DELETE /TN "AMDInstallLauncher" /f

:: Exclui tarefa AMD Link Update.
echo Exclui AMD Link Update.
schtasks /DELETE /TN "AMDLinkUpdate" /f

:: Exclui tarefa AMDRyzenMasterSDKTask.
echo Exclui AMDRyzenMasterSDKTask.
schtasks /DELETE /TN "AMDRyzenMasterSDKTask" /f

:: Exclui tarefa Driver Easy Scheduled Scan.
echo Exclui Driver Easy Scheduled Scan.
schtasks /DELETE /TN "Driver Easy Scheduled Scan" /f

:: Exclui tarefa ModifyLinkUpdate.
echo Exclui ModifyLinkUpdate.
schtasks /DELETE /TN "ModifyLinkUpdate" /f

:: Exclui tarefa SoftMakerUpdater.
echo Exclui SoftMakerUpdater.
schtasks /DELETE /TN "SoftMakerUpdater" /f

:: Exclui tarefa StartCN.
echo Exclui StartCN.
schtasks /DELETE /TN "StartCN" /f

:: Exclui tarefa StartDVR.
echo Exclui StartDVR.
schtasks /DELETE /TN "StartDVR" /f

:: Desabilita avaliador de compatibilidade da Microsoft.
echo Desabilita avaliador de compatibilidade da Microsoft.
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable

:: Desabilita tarefa de patch do banco de dados PCA (Application Experience).
echo Desabilita tarefa de patch do banco de dados PCA.
schtasks /Change /TN "Microsoft\Windows\Application Experience\PcaPatchDbTask" /Disable

:: Desabilita atualizador de dados de programa.
echo Desabilita atualizador de dados de programa.
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable

:: Desabilita tarefa de aplicativo de inicialização.
echo Desabilita tarefa de aplicativo de inicialização.
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable

:: Desabilita tarefa de proxy Autochk.
echo Desabilita tarefa de proxy Autochk.
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable

:: Desabilita consolidador do Programa de Experiência do Cliente.
echo Desabilita consolidador CEIP.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable

:: Desabilita telemetria USB (CEIP).
echo Desabilita telemetria USB CEIP.
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable

:: Desabilita desfragmentação agendada.
echo Desabilita desfragmentação agendada.
schtasks /Change /TN "Microsoft\Windows\Defrag\ScheduledDefrag" /Disable

:: Desabilita tarefa de informações do dispositivo.
echo Desabilita tarefa de info do dispositivo.
schtasks /Change /TN "Microsoft\Windows\Device Information\Device" /Disable

:: Desabilita tarefa de informações do usuário do dispositivo.
echo Desabilita tarefa de info do usuário do dispositivo.
schtasks /Change /TN "Microsoft\Windows\Device Information\Device User" /Disable

:: Desabilita scanner de solução de problemas recomendada.
echo Desabilita scanner de solução de problemas.
schtasks /Change /TN "Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /Disable

:: Desabilita diagnóstico agendado.
echo Desabilita diagnóstico agendado.
schtasks /Change /TN "Microsoft\Windows\Diagnosis\Scheduled" /Disable

:: Desabilita limpeza silenciosa de disco.
echo Desabilita limpeza de disco silenciosa.
schtasks /Change /TN "Microsoft\Windows\DiskCleanup\SilentCleanup" /Disable

:: Desabilita coletor de dados de diagnóstico de disco.
echo Desabilita coletor de diagnóstico de disco.
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable

:: Desabilita diagnósticos de pegada de disco.
echo Desabilita diagnósticos de pegada de disco.
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable

:: Desabilita senso de armazenamento de pegada de disco.
echo Desabilita senso de armazenamento.
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\StorageSense" /Disable

:: Desabilita tarefa DUSM (Data Usage).
echo Desabilita tarefa DUSM.
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable

:: Desabilita tarefa de manutenção MDM (Enterprise Management).
echo Desabilita manutenção MDM.
schtasks /Change /TN "Microsoft\Windows\EnterpriseMgmt\MDMMaintenenceTask" /Disable

:: Desabilita cliente de telemetria de feedback.
echo Desabilita cliente de feedback.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable

:: Desabilita cliente de telemetria de feedback em download de cenário.
echo Desabilita cliente de feedback em download.
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" /Disable

:: Desabilita modo de manutenção do Histórico de Arquivos.
echo Desabilita manutenção Histórico de Arquivos.
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable

:: Desabilita reconciliação de recursos do Flighting (configuração de recursos).
echo Desabilita reconciliação de recursos Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\ReconcileFeatures" /Disable

:: Desabilita descarregamento de dados de uso do Flighting.
echo Desabilita descarregamento dados de uso Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataFlushing" /Disable

:: Desabilita relatório de dados de uso do Flighting.
echo Desabilita relatório dados de uso Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\FeatureConfig\UsageDataReporting" /Disable

:: Desabilita atualização de cache OneSettings do Flighting.
echo Desabilita atualização cache OneSettings Flighting.
schtasks /Change /TN "Microsoft\Windows\Flighting\OneSettings\RefreshCache" /Disable

:: Desabilita sincronização de dados de usuário local (entrada).
echo Desabilita sincronização dados usuário local.
schtasks /Change /TN "Microsoft\Windows\Input\LocalUserSyncDataAvailable" /Disable

:: Desabilita sincronização de dados do mouse (entrada).
echo Desabilita sincronização dados do mouse.
schtasks /Change /TN "Microsoft\Windows\Input\MouseSyncDataAvailable" /Disable

:: Desabilita sincronização de dados de caneta.
echo Desabilita sincronização de dados de caneta.
schtasks /Change /TN "Microsoft\Windows\Input\PenSyncDataAvailable" /Disable

:: Desabilita sincronização de dados de touchpad.
echo Desabilita sincronização de dados de touchpad.
schtasks /Change /TN "Microsoft\Windows\Input\TouchpadSyncDataAvailable" /Disable

:: Desabilita sincronização de configurações de idioma.
echo Desabilita sincronização de idioma.
schtasks /Change /TN "Microsoft\Windows\International\Synchronize Language Settings" /Disable

:: Desabilita instalação de componentes de idioma.
echo Desabilita instalação de idioma.
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Installation" /Disable

:: Desabilita reconciliação de recursos de idioma.
echo Desabilita reconciliação de idioma.
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\ReconcileLanguageResources" /Disable

:: Desabilita desinstalação de componentes de idioma.
echo Desabilita desinstalação de idioma.
schtasks /Change /TN "Microsoft\Windows\LanguageComponentsInstaller\Uninstallation" /Disable

:: Desabilita troca de licença temporária assinada.
echo Desabilita troca de licença temp.
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable

:: Desabilita troca de licença temporária assinada (duplicado).
echo Desabilita troca de licença temp (duplicado).
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /Disable

:: Desabilita provisionamento de celular (Gerenciamento).
echo Desabilita provisionamento de celular.
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Cellular" /Disable

:: Desabilita provisionamento no logon (Gerenciamento).
echo Desabilita provisionamento no logon.
schtasks /Change /TN "Microsoft\Windows\Management\Provisioning\Logon" /Disable

:: Desabilita avaliação de desempenho do sistema (WinSAT).
echo Desabilita avaliação de desempenho (WinSAT).
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable

:: Desabilita tarefa de notificação de Mapas.
echo Desabilita notificação de Mapas.
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable

:: Desabilita tarefa de atualização de Mapas.
echo Desabilita atualização de Mapas.
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable

:: Desabilita parser de metadados de contas de Banda Larga Móvel.
echo Desabilita parser de banda larga móvel.
schtasks /Change /TN "Microsoft\Windows\Mobile Broadband Accounts\MNO Metadata Parser" /Disable

:: Desabilita remoção de pacote de idioma (MUI).
echo Desabilita remoção de pacote de idioma.
schtasks /Change /TN "Microsoft\Windows\MUI\LPRemove" /Disable

:: Desabilita coleta de informações de rede.
echo Desabilita coleta de info de rede.
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable

:: Desabilita tarefas de telemetria de Programa de Experiência do Usuário (PI).
echo Desabilita telemetria PI.
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable

:: Desabilita análise do sistema para diagnóstico de eficiência energética.
echo Desabilita análise de eficiência energética.
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable

:: Desabilita registro de PushToInstall.
echo Desabilita registro PushToInstall.
schtasks /Change /TN "Microsoft\Windows\PushToInstall\Registration" /Disable

:: Desabilita Mobility Manager do RAS.
echo Desabilita Mobility Manager do RAS.
schtasks /Change /TN "Microsoft\Windows\Ras\MobilityManager" /Disable

:: Desabilita verificação do Ambiente de Recuperação do Windows (WinRE).
echo Desabilita verificação WinRE.
schtasks /Change /TN "Microsoft\Windows\RecoveryEnvironment\VerifyWinRE" /Disable

:: Desabilita tarefa de Assistência Remota.
echo Desabilita tarefa de Assistência Remota.
schtasks /Change /TN "Microsoft\Windows\RemoteAssistance\RemoteAssistanceTask" /Disable

:: Desabilita limpeza de conteúdo offline de demonstração de varejo.
echo Desabilita limpeza de demonstração.
schtasks /Change /TN "Microsoft\Windows\RetailDemo\CleanupOfflineContent" /Disable

:: Desabilita limpeza de componentes de serviço.
echo Desabilita limpeza de componentes.
schtasks /Change /TN "Microsoft\Windows\Servicing\StartComponentCleanup" /Disable

:: Desabilita tarefa de mudança de estado de rede da Sincronização de Configurações.
echo Desabilita mudança de estado de rede (Settings Sync).
schtasks /Change /TN "Microsoft\Windows\SettingSync\NetworkStateChangeTask" /Disable

:: Desabilita tarefa de limpeza da Instalação.
echo Desabilita limpeza da Instalação.
schtasks /Change /TN "Microsoft\Windows\Setup\SetupCleanupTask" /Disable

:: Desabilita tarefa de limpeza de instantâneo da Instalação.
echo Desabilita limpeza de instantâneo da Instalação.
schtasks /Change /TN "Microsoft\Windows\Setup\SnapshotCleanupTask" /Disable

:: Desabilita tarefa do Agente SpacePort.
echo Desabilita Agente SpacePort.
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceAgentTask" /Disable

:: Desabilita tarefa do Gerenciador SpacePort.
echo Desabilita Gerenciador SpacePort.
schtasks /Change /TN "Microsoft\Windows\SpacePort\SpaceManagerTask" /Disable

:: Desabilita tarefa de download de modelo de fala.
echo Desabilita download de modelo de fala.
schtasks /Change /TN "Microsoft\Windows\Speech\SpeechModelDownloadTask" /Disable

:: Desabilita inicialização de Gerenciamento de Camadas de Armazenamento.
echo Desabilita inicialização de Gerenciamento de Armazenamento.
schtasks /Change /TN "Microsoft\Windows\Storage Tiers Management\Storage Tiers Management Initialization" /Disable

:: Desabilita sincronização de banco de dados de prioridade do SysMain.
echo Desabilita sincronização de banco de dados SysMain.
schtasks /Change /TN "Microsoft\Windows\Sysmain\ResPriStaticDbSync" /Disable

:: Desabilita tarefa de avaliação de swap do SysMain.
echo Desabilita avaliação de swap SysMain.
schtasks /Change /TN "Microsoft\Windows\Sysmain\WsSwapAssessmentTask" /Disable

:: Desabilita tarefa interativa do Gerenciador de Tarefas.
echo Desabilita tarefa interativa do Gerenciador.
schtasks /Change /TN "Microsoft\Windows\Task Manager\Interactive" /Disable

:: Desabilita forçar sincronização de tempo.
echo Desabilita forçar sincronização de tempo.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable

:: Desabilita sincronização de tempo.
echo Desabilita sincronização de tempo.
schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable

:: Desabilita sincronização de fuso horário.
echo Desabilita sincronização de fuso horário.
schtasks /Change /TN "Microsoft\Windows\Time Zone\SynchronizeTimeZone" /Disable

:: Desabilita recuperação de certificado HAS do TPM.
echo Desabilita recuperação de certificado TPM.
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-HASCertRetr" /Disable

:: Desabilita manutenção do TPM.
echo Desabilita manutenção do TPM.
schtasks /Change /TN "Microsoft\Windows\TPM\Tpm-Maintenance" /Disable

:: Desabilita configuração do host UPnP.
echo Desabilita configuração do host UPnP.
schtasks /Change /TN "Microsoft\Windows\UPnP\UPnPHostConfig" /Disable

:: Desabilita tarefa de upload de Hive do Perfil de Usuário.
echo Desabilita upload de Hive do Perfil de Usuário.
schtasks /Change /TN "Microsoft\Windows\User Profile Service\HiveUploadTask" /Disable

:: Desabilita host de resolução WDI.
echo Desabilita host de resolução WDI.
schtasks /Change /TN "Microsoft\Windows\WDI\ResolutionHost" /Disable

:: Desabilita alteração de tipo de início de serviço BFE (WFP).
echo Desabilita alteração de serviço BFE.
schtasks /Change /TN "Microsoft\Windows\Windows Filtering Platform\BfeOnServiceStartTypeChange" /Disable

:: Desabilita gerenciamento de hash WIM.
echo Desabilita gerenciamento de hash WIM.
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Management" /Disable

:: Desabilita validação de hash WIM.
echo Desabilita validação de hash WIM.
schtasks /Change /TN "Microsoft\Windows\WOF\WIM-Hash-Validation" /Disable

:: Desabilita sincronização de logon de Pastas de Trabalho.
echo Desabilita sincronização de logon de Pastas de Trabalho.
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Logon Synchronization" /Disable

:: Desabilita manutenção de Pastas de Trabalho.
echo Desabilita manutenção de Pastas de Trabalho.
schtasks /Change /TN "Microsoft\Windows\Work Folders\Work Folders Maintenance Work" /Disable

:: Desabilita junção automática de dispositivo no Workplace Join.
echo Desabilita junção automática de dispositivo.
schtasks /Change /TN "Microsoft\Windows\Workplace Join\Automatic-Device-Join" /Disable

:: Desabilita tarefa de notificação do serviço WWAN.
echo Desabilita notificação WWAN.
schtasks /Change /TN "Microsoft\Windows\WwanSvc\NotificationTask" /Disable

:: Desabilita descoberta OOBE do serviço WWAN.
echo Desabilita descoberta OOBE WWAN.
schtasks /Change /TN "Microsoft\Windows\WwanSvc\OobeDiscovery" /Disable

:: Desabilita tarefa de salvamento de jogo Xbox Live.
echo Desabilita salvamento de jogo Xbox Live.
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /Disable

:: Desabilita varredura por atualizações do InstallService.
echo Desabilita varredura por atualizações (InstallService).
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdates" /Disable

:: Desabilita varredura por atualizações como usuário do InstallService.
echo Desabilita varredura por atualizações como usuário (InstallService).
schtasks /Change /TN "Microsoft\Windows\InstallService\ScanForUpdatesAsUser" /Disable

:: Desabilita tentativa inteligente do InstallService.
echo Desabilita tentativa inteligente (InstallService).
schtasks /Change /TN "Microsoft\Windows\InstallService\SmartRetry" /Disable

:: Desabilita despertar e continuar atualizações do InstallService.
echo Desabilita despertar e continuar atualizações (InstallService).
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndContinueUpdates" /Disable

:: Desabilita despertar e escanear por atualizações do InstallService.
echo Desabilita despertar e escanear por atualizações (InstallService).
schtasks /Change /TN "Microsoft\Windows\InstallService\WakeUpAndScanForUpdates" /Disable

:: Desabilita relatório de políticas do Update Orchestrator.
echo Desabilita relatório de políticas (Update Orchestrator).
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Report policies" /Disable

:: Desabilita varredura agendada do Update Orchestrator.
echo Desabilita varredura agendada (Update Orchestrator).
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /Disable

:: Desabilita varredura agendada estática do Update Orchestrator.
echo Desabilita varredura agendada estática (Update Orchestrator).
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan Static Task" /Disable

:: Desabilita tarefa de modelo de atualização do Update Orchestrator.
echo Desabilita tarefa de modelo de atualização (Update Orchestrator).
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\UpdateModelTask" /Disable

:: Desabilita USO_UxBroker do Update Orchestrator.
echo Desabilita USO_UxBroker (Update Orchestrator).
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker" /Disable

:: Desabilita remediação do WaaSMedic.
echo Desabilita remediação WaaSMedic.
schtasks /Change /TN "Microsoft\Windows\WaaSMedic\PerformRemediation" /Disable

:: Desabilita início agendado do Windows Update.
echo Desabilita início agendado do Windows Update.
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /Disable

:: Desabilita provedor de impressão educacional.
echo Desabilita provedor de impressão educacional.
schtasks /Change /TN "Microsoft\Windows\Printing\EduPrintProv" /Disable

:: Desabilita tarefa de limpeza de impressora.
echo Desabilita limpeza de impressora.
schtasks /Change /TN "Microsoft\Windows\Printing\PrinterCleanupTask" /Disable

:: Desabilita sincronização CDS do serviço WLAN.
echo Desabilita sincronização CDS WLAN.
schtasks /Change /TN "Microsoft\Windows\WlanSvc\CDSSync" /Disable

:: Desabilita tarefa Wi-Fi do WCM.
echo Desabilita tarefa Wi-Fi WCM.
schtasks /Change /TN "Microsoft\Windows\WCM\WiFiTask" /Disable

:: Desabilita tarefa Wi-Fi do NlaSvc.
echo Desabilita tarefa Wi-Fi NlaSvc.
schtasks /Change /TN "Microsoft\Windows\NlaSvc\WiFiTask" /Disable

:: Desabilita tarefa DUSM.
echo Desabilita tarefa DUSM.
schtasks /Change /TN "Microsoft\Windows\DUSM\dusmtask" /Disable

:: Assume propriedade da pasta SystemApps.
echo Assumindo propriedade de SystemApps.
takeown /s %computername% /u %username% /f "%WinDir%\SystemApps"

:: Assume propriedade do Broadcastdvr.exe.
echo Assumindo propriedade de Broadcastdvr.exe.
takeown /s %computername% /u %username% /f "%WinDir%\System32\Broadcastdvr.exe"

:: Assume propriedade do upfc.exe.
echo Assumindo propriedade de upfc.exe.
takeown /s %computername% /u %username% /f "%WinDir%\System32\upfc.exe"

:: Assume propriedade do Compatibility Telement.exe.
echo Assumindo propriedade de Compatibility Telement.exe.
takeown /s %computername% /u %username% /f "%WinDir%\System32\Compatibility Telement.exe"

:: Assume propriedade do CompPkgSrv.exe.
echo Assumindo propriedade de CompPkgSrv.exe.
takeown /s %computername% /u %username% /f "%WinDir%\System32\CompPkgSrv.exe"

:: Assume propriedade do mobsync.exe.
echo Assumindo propriedade de mobsync.exe.
takeown /s %computername% /u %username% /f "%WinDir%\System32\mobsync.exe"

:: Assume propriedade do smartscreen.exe.
echo Assumindo propriedade de smartscreen.exe.
takeown /s %computername% /u %username% /f "%WinDir%\System32\smartscreen.exe"

:: Assume propriedade do GameBarPresenceWriter.exe (System32).
echo Assumindo propriedade de GameBarPresenceWriter.exe (System32).
takeown /s %computername% /u %username% /f "%WinDir%\System32\GameBarPresenceWriter.exe"

:: Assume propriedade do GameBarPresenceWriter.exe (Windows).
echo Assumindo propriedade de GameBarPresenceWriter.exe (Windows).
takeown /s %computername% /u %username% /f "%WinDir%\Windows\GameBarPresenceWriter.exe"

:: Assume propriedade da pasta Internet Explorer (Program Files x86).
echo Assumindo propriedade de Internet Explorer (x86).
takeown /s %computername% /u %username% /f "%WinDir%\Program Files (x86)\Internet Explorer"

:: Assume propriedade da pasta Microsoft (Program Files x86).
echo Assumindo propriedade de Microsoft (x86).
takeown /s %computername% /u %username% /f "%WinDir%\Program Files (x86)\Microsoft"

:: Assume propriedade da pasta WindowsApps (Program Files).
echo Assumindo propriedade de WindowsApps.
takeown /s %computername% /u %username% /f "%ProgramFiles%\WindowsApps"

:: Assume propriedade da pasta Internet Explorer (Program Files).
echo Assumindo propriedade de Internet Explorer.
takeown /s %computername% /u %username% /f "%WinDir%\Program Files\Internet Explorer"

:: Assume propriedade da pasta bcastdvr (Windows).
echo Assumindo propriedade de bcastdvr.
takeown /s %computername% /u %username% /f "%WinDir%\Windows\bcastdvr"

:: Assume propriedade da pasta GameDVR do usuário.
echo Assumindo propriedade de GameDVR do usuário.
takeown /s %computername% /u %username% /f "%WinDir%\Users\%username%\AppData\Local\Microsoft\GameDVR"

:: Assume propriedade da pasta Edge do usuário.
echo Assumindo propriedade de Edge do usuário.
takeown /s %computername% /u %username% /f "%WinDir%\Users\%username%\AppData\Local\Microsoft\Edge"

:: Assume propriedade do ShellExperienceHost.exe.
echo Assumindo propriedade de ShellExperienceHost.exe.
takeown /s %computername% /u %username% /f "%WinDir%\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe"

:: Assume propriedade do TextInputHost.exe.
echo Assumindo propriedade de TextInputHost.exe.
takeown /s %computername% /u %username% /f "%WinDir%\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe"

:: Assume propriedade do UserOOBEBroker.exe.
echo Assumindo propriedade de UserOOBEBroker.exe.
takeown /s %computername% /u %username% /f "%WinDir%\Windows\System32\oobe\UserOOBEBroker.exe"

:: Concede Controle Total ao ShellExperienceHost.exe e subitens.
echo Concedendo Controle Total ao ShellExperienceHost.exe e subitens.
icacls "%WinDir%\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao TextInputHost.exe e subitens.
echo Concedendo Controle Total ao TextInputHost.exe e subitens.
icacls "%WinDir%\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao Broadcastdvr.exe e subitens.
echo Concedendo Controle Total ao Broadcastdvr.exe e subitens.
icacls "%WinDir%\System32\Broadcastdvr.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao upfc.exe e subitens.
echo Concedendo Controle Total ao upfc.exe e subitens.
icacls "%WinDir%\System32\upfc.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao Compatibility Telement.exe e subitens.
echo Concedendo Controle Total ao Compatibility Telement.exe e subitens.
icacls "%WinDir%\System32\Compatibility Telement.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao CompPkgSrv.exe e subitens.
echo Concedendo Controle Total ao CompPkgSrv.exe e subitens.
icacls "%WinDir%\System32\CompPkgSrv.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao mobsync.exe e subitens.
echo Concedendo Controle Total ao mobsync.exe e subitens.
icacls "%WinDir%\System32\mobsync.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao smartscreen.exe e subitens.
echo Concedendo Controle Total ao smartscreen.exe e subitens.
icacls "%WinDir%\System32\smartscreen.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao GameBarPresenceWriter.exe (System32) e subitens.
echo Concedendo Controle Total ao GameBarPresenceWriter.exe (System32) e subitens.
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao GameBarPresenceWriter.exe (Windows) e subitens.
echo Concedendo Controle Total ao GameBarPresenceWriter.exe (Windows) e subitens.
icacls "%WinDir%\Windows\GameBarPresenceWriter.exe" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta Internet Explorer (Program Files x86) e subitens.
echo Concedendo Controle Total à pasta Internet Explorer (x86) e subitens.
icacls "%WinDir%\Program Files (x86)\Internet Explorer" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta Microsoft (Program Files x86) e subitens.
echo Concedendo Controle Total à pasta Microsoft (x86) e subitens.
icacls "%WinDir%\Program Files (x86)\Microsoft" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta SystemApps e subitens.
echo Concedendo Controle Total à pasta SystemApps e subitens.
icacls "%WinDir%\SystemApps" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta WindowsApps e subitens.
echo Concedendo Controle Total à pasta WindowsApps e subitens.
icacls "%ProgramFiles%\WindowsApps" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta Internet Explorer (Program Files) e subitens.
echo Concedendo Controle Total ao Internet Explorer e subitens.
icacls "%WinDir%\Program Files\Internet Explorer" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta bcastdvr e subitens.
echo Concedendo Controle Total à pasta bcastdvr e subitens.
icacls "%WinDir%\Windows\bcastdvr" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta GameDVR do usuário e subitens.
echo Concedendo Controle Total à pasta GameDVR do usuário e subitens.
icacls "%WinDir%\Users\%username%\AppData\Local\Microsoft\GameDVR" /grant %username%:F administrators:F /t /c

:: Concede Controle Total à pasta Edge do usuário e subitens.
echo Concedendo Controle Total à pasta Edge do usuário e subitens.
icacls "%WinDir%\Users\%username%\AppData\Local\Microsoft\Edge" /grant %username%:F administrators:F /t /c

:: Concede Controle Total ao UserOOBEBroker.exe e subitens.
echo Concedendo Controle Total ao UserOOBEBroker.exe e subitens.
icacls "%WinDir%\Windows\System32\oobe\UserOOBEBroker.exe" /grant %username%:F administrators:F /t /c

---

:: Define o proprietário da pasta SystemApps e subitens como o usuário atual.
echo Definindo proprietário de SystemApps e subitens.
icacls "%WinDir%\SystemApps" /setowner "%username%" /t

:: Define o proprietário do ShellExperienceHost.exe e subitens como o usuário atual.
echo Definindo proprietário de ShellExperienceHost.exe e subitens.
icacls "%WinDir%\Windows\SystemApps\ShellExperienceHost_cw5n1h2txyewy\ShellExperienceHost.exe" /setowner "%username%" /t

:: Define o proprietário do TextInputHost.exe e subitens como o usuário atual.
echo Definindo proprietário de TextInputHost.exe e subitens.
icacls "%WinDir%\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" /setowner "%username%" /t

:: Define o proprietário do Broadcastdvr.exe e subitens como o usuário atual.
echo Definindo proprietário de Broadcastdvr.exe e subitens.
icacls "%WinDir%\System32\Broadcastdvr.exe" /setowner "%username%" /t

:: Define o proprietário do upfc.exe e subitens como o usuário atual.
echo Definindo proprietário de upfc.exe e subitens.
icacls "%WinDir%\System32\upfc.exe" /setowner "%username%" /t

:: Define o proprietário do Compatibility Telement.exe e subitens como o usuário atual.
echo Definindo proprietário de Compatibility Telement.exe e subitens.
icacls "%WinDir%\System32\Compatibility Telement.exe" /setowner "%username%" /t

:: Define o proprietário do CompPkgSrv.exe e subitens como o usuário atual.
echo Definindo proprietário de CompPkgSrv.exe e subitens.
icacls "%WinDir%\System32\CompPkgSrv.exe" /setowner "%username%" /t

:: Define o proprietário do mobsync.exe e subitens como o usuário atual.
echo Definindo proprietário de mobsync.exe e subitens.
icacls "%WinDir%\System32\mobsync.exe" /setowner "%username%" /t

:: Define o proprietário do smartscreen.exe e subitens como o usuário atual.
echo Definindo proprietário de smartscreen.exe e subitens.
icacls "%WinDir%\System32\smartscreen.exe" /setowner "%username%" /t

:: Define o proprietário do GameBarPresenceWriter.exe e subitens como o usuário atual.
echo Definindo proprietário de GameBarPresenceWriter.exe e subitens.
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /setowner "%username%" /t

:: Define o proprietário do GameBarPresenceWriter.exe (Windows) e subitens como o usuário atual.
echo Definindo proprietário de GameBarPresenceWriter.exe (Windows) e subitens.
icacls "%WinDir%\Windows\GameBarPresenceWriter.exe" /setowner "%username%" /t

:: Define o proprietário da pasta Internet Explorer (Program Files x86) e subitens como o usuário atual.
echo Definindo proprietário de Internet Explorer (x86) e subitens.
icacls "%WinDir%\Program Files (x86)\Internet Explorer" /setowner "%username%" /t

:: Define o proprietário da pasta Microsoft (Program Files x86) e subitens como o usuário atual.
echo Definindo proprietário de Microsoft (x86) e subitens.
icacls "%WinDir%\Program Files (x86)\Microsoft" /setowner "%username%" /t

:: Define o proprietário da pasta WindowsApps e subitens como o usuário atual.
echo Definindo proprietário de WindowsApps e subitens.
icacls "%ProgramFiles%\WindowsApps" /setowner "%username%" /t

:: Define o proprietário da pasta Internet Explorer (Program Files) e subitens como o usuário atual.
echo Definindo proprietário de Internet Explorer e subitens.
icacls "%WinDir%\Program Files\Internet Explorer" /setowner "%username%" /t

:: Define o proprietário da pasta bcastdvr e subitens como o usuário atual.
echo Definindo proprietário de bcastdvr e subitens.
icacls "%WinDir%\Windows\bcastdvr" /setowner "%username%" /t

:: Define o proprietário da pasta GameDVR do usuário e subitens como o usuário atual.
echo Definindo proprietário de GameDVR do usuário e subitens.
icacls "%WinDir%\Users\%username%\AppData\Local\Microsoft\GameDVR" /setowner "%username%" /t

:: Define o proprietário da pasta Edge do usuário e subitens como o usuário atual.
echo Definindo proprietário de Edge do usuário e subitens.
icacls "%WinDir%\Users\%username%\AppData\Local\Microsoft\Edge" /setowner "%username%" /t

:: Define o proprietário do UserOOBEBroker.exe e subitens como o usuário atual.
echo Definindo proprietário de UserOOBEBroker.exe e subitens.
icacls "%WinDir%\Windows\System32\oobe\UserOOBEBroker.exe" /setowner "%username%" /t

:: Concede Controle Total, redefine herança e define proprietário para Broadcastdvr.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para Broadcastdvr.exe e subitens.
icacls "%WinDir%\System32\Broadcastdvr.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para upfc.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para upfc.exe e subitens.
icacls "%WinDir%\System32\upfc.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para Compatibility Telement.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para Compatibility Telement.exe e subitens.
icacls "%WinDir%\System32\Compatibility Telement.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para CompPkgSrv.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para CompPkgSrv.exe e subitens.
icacls "%WinDir%\System32\CompPkgSrv.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para mobsync.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para mobsync.exe e subitens.
icacls "%WinDir%\System32\mobsync.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para smartscreen.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para smartscreen.exe e subitens.
icacls "%WinDir%\System32\smartscreen.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para GameBarPresenceWriter.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para GameBarPresenceWriter.exe e subitens.
icacls "%WinDir%\System32\GameBarPresenceWriter.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para GameBarPresenceWriter.exe (Windows) e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para GameBarPresenceWriter.exe (Windows) e subitens.
icacls "%WinDir%\Windows\GameBarPresenceWriter.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para Internet Explorer (Program Files x86) e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para Internet Explorer (x86) e subitens.
icacls "%WinDir%\Program Files (x86)\Internet Explorer" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para Microsoft (Program Files x86) e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para Microsoft (x86) e subitens.
icacls "%WinDir%\Program Files (x86)\Microsoft" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para WindowsApps e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para WindowsApps e subitens.
icacls "%ProgramFiles%\WindowsApps" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para Internet Explorer (Program Files) e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para Internet Explorer e subitens.
icacls "%WinDir%\Program Files\Internet Explorer" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para bcastdvr e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para bcastdvr e subitens.
icacls "%WinDir%\Windows\bcastdvr" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para GameDVR do usuário e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para GameDVR do usuário e subitens.
icacls "%WinDir%\Users\%username%\AppData\Local\Microsoft\GameDVR" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para Edge do usuário e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para Edge do usuário e subitens.
icacls "%WinDir%\Users\%username%\AppData\Local\Microsoft\Edge" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Concede Controle Total, redefine herança e define proprietário para UserOOBEBroker.exe e subitens.
echo Concedendo Controle Total, redefinindo herança e definindo proprietário para UserOOBEBroker.exe e subitens.
icacls "%WinDir%\Windows\System32\oobe\UserOOBEBroker.exe" /inheritance:r /grant:r %username%:(OI)(CI)F /t /l /q /c

:: Encerra o processo de instalação do OneDrive.
echo Encerrando OneDriveSetup.exe.
taskkill /f /t /IM OneDriveSetup.exe

:: Encerra o processo de Telemetria de Compatibilidade.
echo Encerrando CompatTelRunner.exe.
taskkill /f /t /IM CompatTelRunner.exe

:: Encerra o processo de serviço de pacote de componentes.
echo Encerrando CompPkgSrv.exe.
taskkill /f /t /IM CompPkgSrv.exe

:: Encerra o processo UPFC.
echo Encerrando upfc.exe.
taskkill /f /t /IM upfc.exe

:: Encerra o processo de sincronização móvel.
echo Encerrando mobsync.exe.
taskkill /f /t /IM mobsync.exe

:: Encerra o processo SmartScreen.
echo Encerrando smartscreen.exe.
taskkill /f /t /IM smartscreen.exe

:: Encerra o processo de atualização do Microsoft Edge.
echo Encerrando MicrosoftEdgeUpdate.exe.
taskkill /f /t /IM MicrosoftEdgeUpdate.exe

:: Encerra o processo de captura de tela.
echo Encerrando ScreenClippingHost.exe.
taskkill /f /t /IM ScreenClippingHost.exe

:: Encerra o processo de host de entrada de texto.
echo Encerrando TextInputHost.exe.
taskkill /f /t /IM TextInputHost.exe

:: Encerra o processo de ponte local.
echo Encerrando LocalBridge.exe.
taskkill /f /t /IM LocalBridge.exe

:: Encerra o aplicativo Fotos da Microsoft.
echo Encerrando Microsoft.Photos.exe.
taskkill /f /t /IM Microsoft.Photos.exe

:: Encerra o aplicativo da Loja Windows.
echo Encerrando WinStore.App.exe.
taskkill /f /t /IM WinStore.App.exe

:: Encerra o aplicativo Skype.
echo Encerrando SkypeApp.exe.
taskkill /f /t /IM SkypeApp.exe

:: Encerra o processo de ponte do Skype.
echo Encerrando SkypeBridge.exe.
taskkill /f /t /IM SkypeBridge.exe

:: Encerra o host em segundo plano do Skype.
echo Encerrando SkypeBackgroundHost.exe.
taskkill /f /t /IM SkypeBackgroundHost.exe

:: Encerra o aplicativo UWP do NCSI.
echo Encerrando NcsiUwpApp.exe.
taskkill /f /t /IM NcsiUwpApp.exe

:: Encerra o host de tarefas em segundo plano.
echo Encerrando backgroundTaskHost.exe.
taskkill /f /t /IM backgroundTaskHost.exe

:: Encerra o host de tarefas do Windows.
echo Encerrando taskhostw.exe.
taskkill /f /t /IM taskhostw.exe

:: Encerra o carregador do processador de entrada.
echo Encerrando ctfmon.exe.
taskkill /f /t /IM ctfmon.exe

:: Encerra o processo HxTsr.exe (Mail/Calendar/People).
echo Encerrando HxTsr.exe.
taskkill /f /t /IM HxTsr.exe

:: Encerra o processo HxOutlook.exe (Mail/Calendar/People).
echo Encerrando HxOutlook.exe.
taskkill /f /t /IM HxOutlook.exe

:: Encerra o processo HxCalendarAppImm.exe (Mail/Calendar/People).
echo Encerrando HxCalendarAppImm.exe.
taskkill /f /t /IM HxCalendarAppImm.exe

:: Encerra o processo HxAccounts.exe (Mail/Calendar/People).
echo Encerrando HxAccounts.exe.
taskkill /f /t /IM HxAccounts.exe

:: Encerra o processo GameBarPresenceWriter.exe (barra de jogos).
echo Encerrando GameBarPresenceWriter.exe.
taskkill /f /t /IM GameBarPresenceWriter.exe

:: Exclui recursivamente a pasta Internet Explorer (x86).
echo Excluindo "%windir%\Program Files (x86)\Internet Explorer".
del "%windir%\Program Files (x86)\Internet Explorer" /s /f /q

:: Encerra o processo de atualização do Microsoft Edge.
echo Encerrando MicrosoftEdgeUpdate.exe.
taskkill /f /t /IM MicrosoftEdgeUpdate.exe

:: Exclui recursivamente a pasta Microsoft (x86).
echo Excluindo "%windir%\Program Files (x86)\Microsoft".
del "%windir%\Program Files (x86)\Microsoft" /s /f /q

:: Encerra o processo de atualização do Microsoft Edge (duplicado).
echo Encerrando MicrosoftEdgeUpdate.exe (duplicado).
taskkill /f /t /IM MicrosoftEdgeUpdate.exe

:: Exclui recursivamente a pasta do Microsoft Edge no SystemApps.
echo Excluindo "%windir%\Windows\SystemApps Microsoft.MicrosoftEdge".
del "%windir%\Windows\SystemApps Microsoft.MicrosoftEdge" /s /f /q

:: Exclui recursivamente a pasta Internet Explorer.
echo Excluindo "%windir%\Program Files\Internet Explorer".
del "%windir%\Program Files\Internet Explorer" /s /f /q

:: Exclui recursivamente a pasta bcastdvr.
echo Excluindo "%windir%\Windows\bcastdvr".
del "%windir%\Windows\bcastdvr" /s /f /q

:: Encerra o processo GameBarPresenceWriter.exe (barra de jogos).
echo Encerrando GameBarPresenceWriter.exe.
taskkill /f /t /IM GameBarPresenceWriter.exe

:: Exclui recursivamente a pasta GameBarPresenceWriter (Windows).
echo Excluindo "%windir%\Windows\GameBarPresenceWriter".
del "%windir%\Windows\GameBarPresenceWriter" /s /f /q

:: Encerra o processo CompPkgSrv.exe.
echo Encerrando CompPkgSrv.exe.
taskkill /f /t /IM CompPkgSrv.exe

:: Exclui o arquivo CompatTelRunner.exe.
echo Excluindo "%windir%\Windows\System32\CompatTelRunner.exe".
del "%windir%\Windows\System32\CompatTelRunner.exe" /s /f /q

:: Encerra o processo upfc.exe.
echo Encerrando upfc.exe.
taskkill /f /t /IM upfc.exe

:: Exclui o arquivo upfc.exe.
echo Excluindo "%windir%\Windows\System32\upfc.exe".
del "%windir%\Windows\System32\upfc.exe" /s /f /q

:: Exclui o arquivo CompPkgSrv.exe.
echo Excluindo "%windir%\Windows\System32\CompPkgSrv.exe".
del "%windir%\Windows\System32\CompPkgSrv.exe" /s /f /q

:: Encerra o processo mobsync.exe.
echo Encerrando mobsync.exe.
taskkill /f /t /IM mobsync.exe

:: Exclui o arquivo mobsync.exe.
echo Excluindo "%windir%\Windows\System32\mobsync.exe".
del "%windir%\Windows\System32\mobsync.exe" /s /f /q

:: Encerra o processo smartscreen.exe.
echo Encerrando smartscreen.exe.
taskkill /f /t /IM smartscreen.exe

:: Exclui o arquivo smartscreen.exe.
echo Excluindo "%windir%\Windows\System32\smartscreen.exe".
del "%windir%\Windows\System32\smartscreen.exe" /s /f /q

:: Encerra o processo GameBarPresenceWriter.exe (barra de jogos).
echo Encerrando GameBarPresenceWriter.exe.
taskkill /f /t /IM GameBarPresenceWriter.exe

:: Exclui recursivamente a pasta GameBarPresenceWriter (System32).
echo Excluindo "%windir%\Windows\System32\GameBarPresenceWriter".
del "%windir%\Windows\System32\GameBarPresenceWriter" /s /f /q

:: Exclui recursivamente a pasta GameDVR do usuário.
echo Excluindo "%windir%\Users\%username%\AppData\Local\Microsoft\GameDVR".
del "%windir%\Users\%username%\AppData\Local\Microsoft\GameDVR" /s /f /q

:: Encerra o processo de atualização do Microsoft Edge.
echo Encerrando MicrosoftEdgeUpdate.exe.
taskkill /f /t /IM MicrosoftEdgeUpdate.exe

:: Exclui recursivamente a pasta Edge do usuário.
echo Excluindo "%windir%\Users\%username%\AppData\Local\Microsoft\Edge".
del "%windir%\Users\%username%\AppData\Local\Microsoft\Edge" /s /f /q

:: Encerra o processo StartMenuExperienceHost.exe.
echo Encerrando StartMenuExperienceHost.exe.
taskkill /f /t /IM StartMenuExperienceHost.exe

:: Encerra o processo ScreenClippingHost.exe.
echo Encerrando ScreenClippingHost.exe.
taskkill /f /t /IM ScreenClippingHost.exe

:: Exclui o arquivo StartMenuExperienceHost.exe.
echo Exclindo "%windir%\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe".
del "%windir%\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe" /s /f /q

:: Encerra o processo TextInputHost.exe.
echo Encerrando TextInputHost.exe.
taskkill /f /t /IM TextInputHost.exe

:: Exclui o arquivo TextInputHost.exe.
echo Excluindo "%windir%\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe".
del "%windir%\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe" /s /f /q

:: Remove recursivamente a pasta GameDVR do usuário.
echo Removendo diretório "%windir%\Users\%username%\AppData\Local\Microsoft\GameDVR".
rmdir /S /Q "%windir%\Users\%username%\AppData\Local\Microsoft\GameDVR"

:: Encerra o processo de atualização do Microsoft Edge.
echo Encerrando MicrosoftEdgeUpdate.exe.
taskkill /f /t /IM MicrosoftEdgeUpdate.exe

:: Remove recursivamente a pasta Edge do usuário.
echo Removendo diretório "%windir%\Users\%username%\AppData\Local\Microsoft\Edge".
rmdir /S /Q "%windir%\Users\%username%\AppData\Local\Microsoft\Edge"

:: Remove recursivamente a pasta Internet Explorer (x86).
echo Removendo diretório "%windir%\Program Files (x86)\Internet Explorer".
rmdir /S /Q "%windir%\Program Files (x86)\Internet Explorer"

:: Remove recursivamente a pasta Microsoft (x86).
echo Removendo diretório "%windir%\Program Files (x86)\Microsoft".
rmdir /S /Q "%windir%\Program Files (x86)\Microsoft"

:: Remove recursivamente a pasta do Microsoft Edge no SystemApps.
echo Removendo diretório "%windir%\Windows\SystemApps Microsoft.MicrosoftEdge".
rmdir /S /Q "%windir%\Windows\SystemApps Microsoft.MicrosoftEdge"

:: Remove recursivamente a pasta Internet Explorer.
echo Removendo diretório "%windir%\Program Files\Internet Explorer".
rmdir /S /Q "%windir%\Program Files\Internet Explorer"

:: Encerra o processo GameBarPresenceWriter.exe (barra de jogos).
echo Encerrando GameBarPresenceWriter.exe.
taskkill /f /t /IM GameBarPresenceWriter.exe

:: Remove recursivamente a pasta bcastdvr.
echo Removendo diretório "%windir%\Windows\bcastdvr".
rmdir /S /Q "%windir%\Windows\bcastdvr"

:: Remove recursivamente a pasta GameBarPresenceWriter (Windows).
echo Removendo diretório "%windir%\Windows\GameBarPresenceWriter".
rmdir /S /Q "%windir%\Windows\GameBarPresenceWriter"

:: Encerra o processo CompatTelRunner.exe.
echo Encerrando CompatTelRunner.exe.
taskkill /f /t /IM CompatTelRunner.exe

:: Remove o arquivo CompatTelRunner.exe (rmdir para arquivo não funcionará, manter del ou tratar como del).
echo (Nota: Este comando rmdir para arquivo não é comum, use 'del' se a intenção é excluir o arquivo).
rmdir /S /Q "%windir%\Windows\System32\CompatTelRunner.exe"

:: Encerra o processo upfc.exe.
echo Encerrando upfc.exe.
taskkill /f /t /IM upfc.exe

:: Remove o arquivo upfc.exe (rmdir para arquivo não funcionará, manter del ou tratar como del).
echo (Nota: Este comando rmdir para arquivo não é comum, use 'del' se a intenção é excluir o arquivo).
rmdir /S /Q "%windir%\Windows\System32\upfc.exe"

:: Encerra o processo CompPkgSrv.exe.
echo Encerrando CompPkgSrv.exe.
taskkill /f /t /IM CompPkgSrv.exe

:: Remove o arquivo CompPkgSrv.exe (rmdir para arquivo não funcionará, manter del ou tratar como del).
echo (Nota: Este comando rmdir para arquivo não é comum, use 'del' se a intenção é excluir o arquivo).
rmdir /S /Q "%windir%\Windows\System32\CompPkgSrv.exe"

:: Encerra o processo mobsync.exe.
echo Encerrando mobsync.exe.
taskkill /f /t /IM mobsync.exe

:: Remove o arquivo mobsync.exe (rmdir para arquivo não funcionará, manter del ou tratar como del).
echo (Nota: Este comando rmdir para arquivo não é comum, use 'del' se a intenção é excluir o arquivo).
rmdir /S /Q "%windir%\Windows\System32\mobsync.exe"

:: Encerra o processo smartscreen.exe.
echo Encerrando smartscreen.exe.
taskkill /f /t /IM smartscreen.exe

:: Remove o arquivo smartscreen.exe (rmdir para arquivo não funcionará, manter del ou tratar como del).
echo (Nota: Este comando rmdir para arquivo não é comum, use 'del' se a intenção é excluir o arquivo).
rmdir /S /Q "%windir%\Windows\System32\smartscreen.exe"

:: Encerra o processo GameBarPresenceWriter.exe (barra de jogos).
echo Encerrando GameBarPresenceWriter.exe.
taskkill /f /t /IM GameBarPresenceWriter.exe

:: Remove recursivamente a pasta GameBarPresenceWriter (System32).
echo Removendo diretório "%windir%\Windows\System32\GameBarPresenceWriter".
rmdir /S /Q "%windir%\Windows\System32\GameBarPresenceWriter"

:: Encerra o processo StartMenuExperienceHost.exe.
echo Encerrando StartMenuExperienceHost.exe.
taskkill /f /t /IM StartMenuExperienceHost.exe

:: Encerra o processo ScreenClippingHost.exe.
echo Encerrando ScreenClippingHost.exe.
taskkill /f /t /IM ScreenClippingHost.exe

:: Remove o arquivo StartMenuExperienceHost.exe (rmdir para arquivo não funcionará, manter del ou tratar como del).
echo (Nota: Este comando rmdir para arquivo não é comum, use 'del' se a intenção é excluir o arquivo).
rmdir /S /Q "%windir%\Windows\SystemApps\Microsoft.Windows.StartMenuExperienceHost_cw5n1h2txyewy\StartMenuExperienceHost.exe"

:: Encerra o processo TextInputHost.exe.
echo Encerrando TextInputHost.exe.
taskkill /f /t /IM TextInputHost.exe

:: Remove o arquivo TextInputHost.exe (rmdir para arquivo não funcionará, manter del ou tratar como del).
echo (Nota: Este comando rmdir para arquivo não é comum, use 'del' se a intenção é excluir o arquivo).
rmdir /S /Q "%windir%\Windows\SystemApps\MicrosoftWindows.Client.CBS_cw5n1h2txyewy\TextInputHost.exe"
:: Desabilita o recurso "Cliente de Impressão na Internet".
echo Desabilitando "Internet Printing Client".
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-InternetPrinting-Client" /NoRestart

:: Desabilita o recurso "Serviço de Impressão LPD".
echo Desabilitando "LPD Print Service".
dism /Online /Disable-Feature /FeatureName:"LPDPrintService" /NoRestart

:: Desabilita o recurso "Monitor de Porta LPR".
echo Desabilitando "LPR Port Monitor".
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-LPRPortMonitor" /NoRestart

:: Desabilita o recurso "Microsoft Print to PDF".
echo Desabilitando "Microsoft Print to PDF".
dism /Online /Disable-Feature /FeatureName:"Printing-PrintToPDFServices-Features" /NoRestart

:: Desabilita o recurso "Serviços XPS".
echo Desabilitando "XPS Services".
dism /Online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /NoRestart

:: Desabilita o recurso "Visualizador XPS".
echo Desabilitando "XPS Viewer".
dism /Online /Disable-Feature /FeatureName:"Xps-Foundation-Xps-Viewer" /NoRestart

:: Desabilita o recurso "Serviços de Impressão e Documentos".
echo Desabilitando "Print and Document Services".
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-Features" /NoRestart

:: Desabilita o recurso "Cliente de Pastas de Trabalho".
echo Desabilitando "Work Folders Client".
dism /Online /Disable-Feature /FeatureName:"WorkFolders-Client" /NoRestart

:: Remove pacotes de telemetria da Nvidia.
echo Removendo pacotes de telemetria Nvidia.
if exist "%ProgramFiles%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL" (
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetryContainer
    rundll32 "%PROGRAMFILES%\NVIDIA Corporation\Installer2\InstallerCore\NVI2.DLL",UninstallPackage NvTelemetry
)

:: Limpa arquivos residuais de telemetria da Nvidia.
echo Limpando arquivos residuais de telemetria Nvidia.
del /s %SystemRoot%\System32\DriverStore\FileRepository\NvTelemetry*.dll
rmdir /s /q "%ProgramFiles(x86)%\NVIDIA Corporation\NvTelemetry" 2>nul
rmdir /s /q "%ProgramFiles%\NVIDIA Corporation\NvTelemetry" 2>nul

:: Desabilita a participação na telemetria da Nvidia via registro.
echo Desabilitando participação na telemetria Nvidia (registro).
reg add "HKLM\SOFTWARE\NVIDIA Corporation\NvControlPanel2\Client" /v "OptInOrOutPreference" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID44231" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID64640" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\NVIDIA Corporation\Global\FTS" /v "EnableRID66610" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\nvlddmkm\Global\Startup" /v "SendTelemetryData" /t REG_DWORD /d 0 /f

:: Desabilita o serviço "NvTelemetryContainer" da Nvidia.
echo Desabilitando serviço "NvTelemetryContainer" da Nvidia.
PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'NvTelemetryContainer'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"

:: Desabilita tarefa agendada de monitoramento de telemetria da Nvidia.
echo Desabilitando tarefa NvTmMon.
schtasks /change /TN NvTmMon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE

:: Desabilita tarefa agendada de relatório de telemetria da Nvidia.
echo Desabilitando tarefa NvTmRep.
schtasks /change /TN NvTmRep_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE

:: Desabilita tarefa agendada de relatório de telemetria da Nvidia no logon.
echo Desabilitando tarefa NvTmRepOnLogon.
schtasks /change /TN NvTmRepOnLogon_{B2FE1952-0186-46C3-BAEC-A80AA35AC5B8} /DISABLE
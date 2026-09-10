#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules ActiveDirectory,GroupPolicy

<#
.SYNOPSIS
  Aplica/actualiza la GPO completa GPO_CZ_BROWSERS desde cualquier DC/host con RSAT.

.DESCRIPTION
  GPO objetivo:
    Dominio : corp.callzilla.net
    Nombre  : GPO_CZ_BROWSERS
    GUID    : 578C78CF-DDAE-48D2-9B85-AE7F22CA403C

  Incluye:
    - Chrome, Edge y Firefox en Computer Configuration.
    - URLBlocklist / WebsiteFilter normalizados.
    - Bloqueo de modo Incognito/InPrivate/Private Browsing.
    - Guest Mode deshabilitado.
    - Homepage/New Tab/Startup/Search.
    - Extension allowlist/forcelist corregidas.
    - Limpieza de configuraciones User heredadas.
    - Limpieza SOLO de cache al cerrar los 3 navegadores.
    - Cookies, sesiones, historial, formularios y contrasenas preservados.
    - Background Mode deshabilitado en Chrome/Edge y Startup Boost en Edge.
    - Backup PRE y reportes POST.
    - Reintentos automaticos frente a 0x80070020/0x80070005.
    - Todas las modificaciones se realizan contra el PDC Emulator detectado.

.NOTES
  La GPO retirada:
    30E8EC6A-8729-439B-82AC-00FE57DA16FE
  NO se modifica.
#>

[CmdletBinding()]
param(
    [ValidateSet('Deploy','Audit')]
    [string]$Mode = 'Deploy',

    [switch]$EnforceExtensionAllowlistOnly,
    [switch]$SyncReplication,
    [switch]$RefreshThisComputer,

    [string]$BackupRoot = 'C:\GPO_Backups\GPO_CZ_BROWSERS'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# OBJETIVO FIJO / PROTECCIONES
# ---------------------------------------------------------------------------
$DomainName      = 'corp.callzilla.net'
$GpoName         = 'GPO_CZ_BROWSERS'
$ExpectedGpoGuid = [Guid]'578C78CF-DDAE-48D2-9B85-AE7F22CA403C'
$RetiredGpoGuid  = [Guid]'30E8EC6A-8729-439B-82AC-00FE57DA16FE'
$LinkOrder       = 4

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Test-IsRetryableGpError {
    param([Parameter(Mandatory)]$ErrorRecord)

    $message = [string]$ErrorRecord.Exception.Message
    $hresult = $ErrorRecord.Exception.HResult

    return (
        $hresult -eq -2147024864 -or  # 0x80070020 sharing violation
        $hresult -eq -2147024891 -or  # 0x80070005 access denied (transient Registry.pol collision observed)
        $message -match '0x80070020|0x80070005|being used by another process|Access is denied'
    )
}

function Invoke-GPRegistryRetry {
    param(
        [Parameter(Mandatory)][hashtable]$Parameters,
        [Parameter(Mandatory)][string]$Description,
        [int]$MaxAttempts = 10
    )

    $Parameters.Guid        = $script:GpoGuid
    $Parameters.Domain      = $script:DomainName
    $Parameters.Server      = $script:Pdc
    $Parameters.ErrorAction = 'Stop'

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        try {
            Set-GPRegistryValue @Parameters | Out-Null
            Write-Host "[OK] $Description" -ForegroundColor Green
            Start-Sleep -Milliseconds 700
            return
        }
        catch {
            if (-not (Test-IsRetryableGpError $_) -or $attempt -eq $MaxAttempts) {
                throw
            }

            Write-Warning "Registry.pol ocupado/bloqueado. Reintento $attempt/$MaxAttempts : $Description"
            Start-Sleep -Seconds 3
        }
    }
}

function Set-GpoValue {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)]
        [ValidateSet('String','DWord','ExpandString','MultiString','QWord','Binary')]
        [string]$Type,
        [Parameter(Mandatory)][string]$Description
    )

    Invoke-GPRegistryRetry -Description $Description -Parameters @{
        Key       = $Key
        ValueName = $ValueName
        Value     = $Value
        Type      = $Type
    }
}

function Disable-GpoValue {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string[]]$ValueName,
        [Parameter(Mandatory)][string]$Description
    )

    Invoke-GPRegistryRetry -Description $Description -Parameters @{
        Key       = $Key
        ValueName = $ValueName
        Disable   = $true
    }
}

function Disable-GpoKeyValues {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$Description
    )

    Invoke-GPRegistryRetry -Description $Description -Parameters @{
        Key     = $Key
        Disable = $true
    }
}

function Set-GpoStringList {
    param(
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string[]]$Values,
        [Parameter(Mandatory)][string]$Description,
        [int]$ClearThroughIndex = 200
    )

    # Elimina indices antiguos en UNA sola llamada y escribe toda la nueva lista
    # en otra llamada. Reduce bloqueos de Registry.pol.
    $oldNames = @(
        for ($i = 1; $i -le $ClearThroughIndex; $i++) { [string]$i }
    )

    Disable-GpoValue `
        -Key $Key `
        -ValueName $oldNames `
        -Description "$Description - limpiar indices anteriores"

    if ($Values.Count -gt 0) {
        $names = @(
            for ($i = 1; $i -le $Values.Count; $i++) { [string]$i }
        )
        $cleanValues = @($Values | ForEach-Object { $_.Trim() })

        Invoke-GPRegistryRetry -Description $Description -Parameters @{
            Key       = $Key
            ValueName = $names
            Value     = $cleanValues
            Type      = 'String'
        }
    }
}

# ---------------------------------------------------------------------------
# DATOS DE LA GPO
# ---------------------------------------------------------------------------
$ChromiumBlockedPatterns = @(
    'www.google.com/doodles',
    'www.google.com/logos',
    'www.google.com/fbx',
    'dailygames.discover.google.com',
    'doodles.google.com',
    'doodles.google',
    'elgoog.im',
    'gemini.google.com',
    'bard.google.com',
    'sites.google.com/view/classroom6x',
    'sites.google.com/site/populardoodlegames',
    'googleblog.blogspot.com/2010/05/celebrating-pac-mans-30th-birthday.html'
)

$FirefoxBlockedPatterns = @(
    '*://www.google.com/doodles/*',
    '*://www.google.com/logos/*',
    '*://www.google.com/fbx*',
    '*://dailygames.discover.google.com/*',
    '*://doodles.google.com/*',
    '*://doodles.google/*',
    '*://*.elgoog.im/*',
    '*://gemini.google.com/*',
    '*://bard.google.com/*',
    '*://sites.google.com/view/classroom6x*',
    '*://sites.google.com/site/populardoodlegames*',
    '*://googleblog.blogspot.com/2010/05/celebrating-pac-mans-30th-birthday.html*'
)

$ChromeExtensionAllowlist = @(
    'eoeddkppcaagdeafjfiopeldffkhjodl',
    'ldionhpnclplifljglbnheejfmfhpaag',
    'mbdegapampkgaclohepfibppdhongjgh',
    'ngbpgodhlooghejbkbdmliheebamjeeb',
    'kbfnbcaeplbcioakkpcpgfkobkghlhen',
    'npnbdojkgkbcdfdjlfdmplppdphlhhcf',
    'dihhcbokikbcdfgplefefpibhpnfdono'
)

$ChromeExtensionForcelist = @(
    'mbdegapampkgaclohepfibppdhongjgh;https://clients2.google.com/service/update2/crx',
    'ngbpgodhlooghejbkbdmliheebamjeeb;https://clients2.google.com/service/update2/crx',
    'bhghoamapcdpbohphigoooaddinpkbai;https://clients2.google.com/service/update2/crx',
    'dihhcbokikbcdfgplefefpibhpnfdono',
    'kbfnbcaeplbcioakkpcpgfkobkghlhen'
)

$EdgeExtensionAllowlist = @(
    'kagpabjoboikccfdghpdlaaopmgpgfdc',
    'ckhgbbanigpkebahlfehgaegmepacdeo',
    'pbbjjnjikpfdhmafpjooclchedndmkdl',
    'cnlefmmeadmemmdciolhbnfeacpdfbkd',
    'ljhbidbijmhfjfoohfpoiimfbkheifdn',
    'ocglkepbibnalbgmbachknglpdipeoio',
    'ajdpfmkffanmkhejnopjppegokpogffp'
)

# ---------------------------------------------------------------------------
# VALIDACION
# ---------------------------------------------------------------------------
Write-Step 'Validando dominio, PDC y GPO activa'

Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$Domain = Get-ADDomain -Identity $DomainName -ErrorAction Stop
if ($Domain.DNSRoot -ne $DomainName) {
    throw "SEGURIDAD: dominio detectado '$($Domain.DNSRoot)' distinto de '$DomainName'."
}

$DomainDn = $Domain.DistinguishedName
$Pdc      = $Domain.PDCEmulator

$Gpo = Get-GPO -Name $GpoName -Domain $DomainName -Server $Pdc -ErrorAction Stop

if ($Gpo.Id -eq $RetiredGpoGuid) {
    throw "SEGURIDAD: se detecto el GUID de la GPO RETIRADA. No se haran cambios."
}
if ($Gpo.Id -ne $ExpectedGpoGuid) {
    throw "SEGURIDAD: '$GpoName' tiene GUID $($Gpo.Id), esperado $ExpectedGpoGuid. No se haran cambios."
}

$GpoGuid = $Gpo.Id

$LocalDc = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue
$Inheritance = Get-GPInheritance -Target $DomainDn -Domain $DomainName -Server $Pdc
$Links = @($Inheritance.GpoLinks | Where-Object { $_.GpoId -eq $GpoGuid })

Write-Host "Dominio       : $DomainName"
Write-Host "PDC Emulator  : $Pdc"
Write-Host "Ejecucion     : $env:COMPUTERNAME"
Write-Host "GPO           : $($Gpo.DisplayName)"
Write-Host "GUID          : $($Gpo.Id)"
Write-Host "GPO Status    : $($Gpo.GpoStatus)"
Write-Host "Link target   : $DomainDn"
if ($Links.Count -eq 1) {
    Write-Host "Link order    : $($Links[0].Order)"
    Write-Host "Link enabled  : $($Links[0].Enabled)"
    Write-Host "Link enforced : $($Links[0].Enforced)"
} elseif ($Links.Count -eq 0) {
    Write-Warning "La GPO no tiene enlace directo a la raiz del dominio; se creara en Deploy."
} else {
    throw "SEGURIDAD: se detectaron multiples enlaces directos de la misma GPO a la raiz del dominio."
}
Write-Host "Extension Allow-Only : $($EnforceExtensionAllowlistOnly.IsPresent)"

if ($null -eq $LocalDc) {
    Write-Warning "Este host no aparece como DC. El script puede continuar si tiene RSAT y conectividad al PDC."
}

if ($Mode -eq 'Audit') {
    Write-Warning 'AUDIT: no se realizaron cambios.'
    return
}

# ---------------------------------------------------------------------------
# BACKUP PRE
# ---------------------------------------------------------------------------
$TimeStamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$BackupPath = Join-Path $BackupRoot $TimeStamp

Write-Step 'Backup PRE de la GPO'
New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null

Backup-GPO `
    -Guid $GpoGuid `
    -Domain $DomainName `
    -Server $Pdc `
    -Path $BackupPath `
    -Comment "PRE - Aplicacion completa GPO_CZ_BROWSERS $TimeStamp" |
    Out-Null

Get-GPOReport -Guid $GpoGuid -Domain $DomainName -Server $Pdc `
    -ReportType Xml -Path (Join-Path $BackupPath 'PRE_GPO_Report.xml')

Get-GPOReport -Guid $GpoGuid -Domain $DomainName -Server $Pdc `
    -ReportType Html -Path (Join-Path $BackupPath 'PRE_GPO_Report.html')

# ---------------------------------------------------------------------------
# USER CONFIGURATION - LIMPIEZA DE RESIDUOS HEREDADOS
# ---------------------------------------------------------------------------
Write-Step 'Limpiando configuraciones User heredadas'

$ChromeUserKey = 'HKCU\Software\Policies\Google\Chrome'
Disable-GpoValue -Key $ChromeUserKey -ValueName @(
    'SigninAllowed',
    'IncognitoModeAvailability',
    'DefaultSearchProviderKeyword',
    'DefaultSearchProviderName',
    'DefaultSearchProviderNewTabURL',
    'DefaultSearchProviderSearchURL',
    'DefaultSearchProviderSuggestURL',
    'DefaultSearchProviderEnabled',
    'AmbientAuthenticationInPrivateModesEnabled',
    'BrowserGuestModeEnabled',
    'BrowserGuestModeEnforced',
    'BackgroundModeEnabled'
) -Description 'User/Chrome: limpiar valores heredados'

foreach ($key in @(
    'HKCU\Software\Policies\Google\Chrome\DefaultSearchProviderAlternateURLs',
    'HKCU\Software\Policies\Google\Chrome\ExtensionInstallAllowlist',
    'HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKCU\Software\Policies\Google\Chrome\ExtensionInstallBlocklist',
    'HKCU\Software\Policies\Google\Chrome\RestoreOnStartupURLs',
    'HKCU\Software\Policies\Google\Chrome\URLBlocklist',
    'HKCU\Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList'
)) {
    Disable-GpoKeyValues -Key $key -Description "User/Chrome: limpiar $key"
}

$EdgeUserKey = 'HKCU\Software\Policies\Microsoft\Edge'
Disable-GpoValue -Key $EdgeUserKey -ValueName @(
    'BrowserGuestModeEnabled',
    'InPrivateModeAvailability',
    'HomepageLocation',
    'NewTabPageLocation',
    'RestoreOnStartup',
    'ClearCachedImagesAndFilesOnExit',
    'ClearBrowsingDataOnExit',
    'BackgroundModeEnabled',
    'StartupBoostEnabled'
) -Description 'User/Edge: limpiar valores heredados'

foreach ($key in @(
    'HKCU\Software\Policies\Microsoft\Edge\ExtensionAllowedTypes',
    'HKCU\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist',
    'HKCU\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist',
    'HKCU\Software\Policies\Microsoft\Edge\URLBlocklist'
)) {
    Disable-GpoKeyValues -Key $key -Description "User/Edge: limpiar $key"
}

$FirefoxUserKey = 'HKCU\Software\Policies\Mozilla\Firefox'
Disable-GpoValue -Key $FirefoxUserKey -ValueName @(
    'DisablePrivateBrowsing',
    'PrivateBrowsingModeAvailability'
) -Description 'User/Firefox: limpiar valores heredados'

foreach ($key in @(
    'HKCU\Software\Policies\Mozilla\Firefox\Extensions\Install',
    'HKCU\Software\Policies\Mozilla\Firefox\Homepage',
    'HKCU\Software\Policies\Mozilla\Firefox\WebsiteFilter\Block',
    'HKCU\Software\Policies\Mozilla\Firefox\SanitizeOnShutdown'
)) {
    Disable-GpoKeyValues -Key $key -Description "User/Firefox: limpiar $key"
}

# ---------------------------------------------------------------------------
# CHROME - COMPUTER CONFIGURATION
# ---------------------------------------------------------------------------
Write-Step 'Aplicando Google Chrome'

$ChromeKey = 'HKLM\Software\Policies\Google\Chrome'

Set-GpoValue -Key $ChromeKey -ValueName 'BrowserGuestModeEnabled' -Value 0 -Type DWord `
    -Description 'Chrome: Guest Mode deshabilitado'

Set-GpoValue -Key $ChromeKey -ValueName 'BrowserGuestModeEnforced' -Value 0 -Type DWord `
    -Description 'Chrome: no forzar Guest Mode'

Set-GpoValue -Key $ChromeKey -ValueName 'IncognitoModeAvailability' -Value 1 -Type DWord `
    -Description 'Chrome: Incognito deshabilitado'

Set-GpoValue -Key $ChromeKey -ValueName 'HomepageLocation' -Value 'https://www.google.com/' -Type String `
    -Description 'Chrome: Homepage'

Set-GpoValue -Key $ChromeKey -ValueName 'NewTabPageLocation' -Value 'https://www.callzilla.cx/' -Type String `
    -Description 'Chrome: New Tab'

Set-GpoValue -Key $ChromeKey -ValueName 'RestoreOnStartup' -Value 4 -Type DWord `
    -Description 'Chrome: abrir URL definida al iniciar'

Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Google\Chrome\RestoreOnStartupURLs' `
    -Values @('https://www.google.com/') `
    -Description 'Chrome: Startup URLs' `
    -ClearThroughIndex 30

# Cache SOLO al cerrar.
Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList' `
    -Values @('cached_images_and_files') `
    -Description 'Chrome: borrar SOLO cache al cerrar' `
    -ClearThroughIndex 20

Set-GpoValue -Key $ChromeKey -ValueName 'BackgroundModeEnabled' -Value 0 -Type DWord `
    -Description 'Chrome: deshabilitar Background Mode'

Set-GpoValue -Key $ChromeKey -ValueName 'DefaultSearchProviderEnabled' -Value 1 -Type DWord `
    -Description 'Chrome: Search Provider habilitado'

Set-GpoValue -Key $ChromeKey -ValueName 'DefaultSearchProviderName' -Value 'Callzilla Safe Search' -Type String `
    -Description 'Chrome: Search Provider name'

Set-GpoValue -Key $ChromeKey -ValueName 'DefaultSearchProviderKeyword' -Value '@webonly' -Type String `
    -Description 'Chrome: Search Provider keyword'

Set-GpoValue -Key $ChromeKey -ValueName 'DefaultSearchProviderSearchURL' `
    -Value 'https://www.google.com/search?q={searchTerms}&udm=14' -Type String `
    -Description 'Chrome: Search Provider URL'

Set-GpoValue -Key $ChromeKey -ValueName 'DefaultSearchProviderSuggestURL' `
    -Value 'https://www.google.com/complete/search?output=chrome&q={searchTerms}' -Type String `
    -Description 'Chrome: Search Suggest URL'

Disable-GpoValue -Key $ChromeKey -ValueName @('DefaultSearchProviderNewTabURL') `
    -Description 'Chrome: limpiar Search Provider NewTab URL antigua'

Disable-GpoKeyValues -Key 'HKLM\Software\Policies\Google\Chrome\DefaultSearchProviderAlternateURLs' `
    -Description 'Chrome: limpiar Search Alternate URLs'

Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Google\Chrome\URLBlocklist' `
    -Values $ChromiumBlockedPatterns `
    -Description 'Chrome: URLBlocklist' `
    -ClearThroughIndex 250

Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallAllowlist' `
    -Values $ChromeExtensionAllowlist `
    -Description 'Chrome: ExtensionInstallAllowlist' `
    -ClearThroughIndex 100

Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist' `
    -Values $ChromeExtensionForcelist `
    -Description 'Chrome: ExtensionInstallForcelist' `
    -ClearThroughIndex 100

if ($EnforceExtensionAllowlistOnly) {
    Set-GpoStringList `
        -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallBlocklist' `
        -Values @('*') `
        -Description 'Chrome: bloquear extensiones fuera de allowlist' `
        -ClearThroughIndex 20
} else {
    Disable-GpoKeyValues `
        -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallBlocklist' `
        -Description 'Chrome: no aplicar bloqueo global de extensiones'
}

# ---------------------------------------------------------------------------
# EDGE - COMPUTER CONFIGURATION
# ---------------------------------------------------------------------------
Write-Step 'Aplicando Microsoft Edge'

$EdgeKey = 'HKLM\Software\Policies\Microsoft\Edge'

Set-GpoValue -Key $EdgeKey -ValueName 'BrowserGuestModeEnabled' -Value 0 -Type DWord `
    -Description 'Edge: Guest Mode deshabilitado'

Set-GpoValue -Key $EdgeKey -ValueName 'InPrivateModeAvailability' -Value 1 -Type DWord `
    -Description 'Edge: InPrivate deshabilitado'

Set-GpoValue -Key $EdgeKey -ValueName 'HomepageLocation' -Value 'https://www.google.com/' -Type String `
    -Description 'Edge: Homepage'

Set-GpoValue -Key $EdgeKey -ValueName 'NewTabPageLocation' -Value 'https://www.google.com/' -Type String `
    -Description 'Edge: New Tab'

Set-GpoValue -Key $EdgeKey -ValueName 'RestoreOnStartup' -Value 5 -Type DWord `
    -Description 'Edge: RestoreOnStartup'

# No habilitar ClearBrowsingDataOnExit: borraria todos los datos.
Disable-GpoValue -Key $EdgeKey -ValueName @('ClearBrowsingDataOnExit') `
    -Description 'Edge: impedir borrado de TODOS los datos al cerrar'

Set-GpoValue -Key $EdgeKey -ValueName 'ClearCachedImagesAndFilesOnExit' -Value 1 -Type DWord `
    -Description 'Edge: borrar SOLO cache al cerrar'

Set-GpoValue -Key $EdgeKey -ValueName 'BackgroundModeEnabled' -Value 0 -Type DWord `
    -Description 'Edge: deshabilitar Background Mode'

Set-GpoValue -Key $EdgeKey -ValueName 'StartupBoostEnabled' -Value 0 -Type DWord `
    -Description 'Edge: deshabilitar Startup Boost'

Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Microsoft\Edge\URLBlocklist' `
    -Values $ChromiumBlockedPatterns `
    -Description 'Edge: URLBlocklist' `
    -ClearThroughIndex 250

Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist' `
    -Values $EdgeExtensionAllowlist `
    -Description 'Edge: ExtensionInstallAllowlist' `
    -ClearThroughIndex 100

if ($EnforceExtensionAllowlistOnly) {
    Set-GpoStringList `
        -Key 'HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' `
        -Values @('*') `
        -Description 'Edge: bloquear extensiones fuera de allowlist' `
        -ClearThroughIndex 20
} else {
    Disable-GpoKeyValues `
        -Key 'HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' `
        -Description 'Edge: no aplicar bloqueo global de extensiones'
}

# Limpieza EdgeHTML antiguo.
Disable-GpoValue `
    -Key 'HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main' `
    -ValueName @('AllowInPrivate') `
    -Description 'Edge legado: limpiar AllowInPrivate'

Disable-GpoValue `
    -Key 'HKLM\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings' `
    -ValueName @('HomeButtonURL') `
    -Description 'Edge legado: limpiar HomeButtonURL'

# ---------------------------------------------------------------------------
# FIREFOX - COMPUTER CONFIGURATION
# ---------------------------------------------------------------------------
Write-Step 'Aplicando Mozilla Firefox'

$FirefoxKey = 'HKLM\Software\Policies\Mozilla\Firefox'
$FirefoxSanitizeKey = "$FirefoxKey\SanitizeOnShutdown"

Set-GpoValue -Key $FirefoxKey -ValueName 'PrivateBrowsingModeAvailability' -Value 1 -Type DWord `
    -Description 'Firefox: Private Browsing deshabilitado (actual)'

Set-GpoValue -Key $FirefoxKey -ValueName 'DisablePrivateBrowsing' -Value 1 -Type DWord `
    -Description 'Firefox: Private Browsing deshabilitado (compatibilidad)'

# IMPORTANTE:
# No se intenta Set-GPRegistryValue -Disable sobre el VALOR padre "SanitizeOnShutdown",
# porque en este entorno produjo 0x80070005 al coexistir con la subclave del mismo nombre.
# La configuracion selectiva oficial se escribe directamente en la subclave:
#   SanitizeOnShutdown\Cache, Cookies, FormData, History, Sessions, SiteSettings, Locked.
$FirefoxSanitize = [ordered]@{
    Cache        = 1
    Cookies      = 0
    FormData     = 0
    History      = 0
    Sessions     = 0
    SiteSettings = 0
    Locked       = 1
}

foreach ($name in $FirefoxSanitize.Keys) {
    Set-GpoValue `
        -Key $FirefoxSanitizeKey `
        -ValueName $name `
        -Value $FirefoxSanitize[$name] `
        -Type DWord `
        -Description "Firefox: SanitizeOnShutdown\$name = $($FirefoxSanitize[$name])"
}

Set-GpoValue `
    -Key 'HKLM\Software\Policies\Mozilla\Firefox\Homepage' `
    -ValueName 'URL' `
    -Value 'https://www.google.com/' `
    -Type String `
    -Description 'Firefox: Homepage URL'

Set-GpoValue `
    -Key 'HKLM\Software\Policies\Mozilla\Firefox\Homepage' `
    -ValueName 'Locked' `
    -Value 1 `
    -Type DWord `
    -Description 'Firefox: Homepage Locked'

Set-GpoValue `
    -Key 'HKLM\Software\Policies\Mozilla\Firefox\Homepage' `
    -ValueName 'StartPage' `
    -Value 'homepage-locked' `
    -Type String `
    -Description 'Firefox: Homepage StartPage'

Set-GpoStringList `
    -Key 'HKLM\Software\Policies\Mozilla\Firefox\WebsiteFilter\Block' `
    -Values $FirefoxBlockedPatterns `
    -Description 'Firefox: WebsiteFilter Block' `
    -ClearThroughIndex 250

Disable-GpoValue `
    -Key $FirefoxKey `
    -ValueName @('DisableFirefoxAccounts') `
    -Description 'Firefox: limpiar DisableFirefoxAccounts heredado'

Disable-GpoKeyValues `
    -Key 'HKLM\Software\Policies\Mozilla\Firefox\Extensions\Install' `
    -Description 'Firefox: limpiar Extensions Install heredado/no valido'

# ---------------------------------------------------------------------------
# ENLACE
# ---------------------------------------------------------------------------
Write-Step 'Validando enlace de la GPO'

$Inheritance = Get-GPInheritance -Target $DomainDn -Domain $DomainName -Server $Pdc
$Links = @($Inheritance.GpoLinks | Where-Object { $_.GpoId -eq $GpoGuid })

if ($Links.Count -eq 0) {
    New-GPLink `
        -Guid $GpoGuid `
        -Domain $DomainName `
        -Server $Pdc `
        -Target $DomainDn `
        -LinkEnabled Yes `
        -Enforced No `
        -Order $LinkOrder |
        Out-Null
}
elseif ($Links.Count -eq 1) {
    Set-GPLink `
        -Guid $GpoGuid `
        -Domain $DomainName `
        -Server $Pdc `
        -Target $DomainDn `
        -LinkEnabled Yes `
        -Enforced No `
        -Order $LinkOrder |
        Out-Null
}
else {
    throw 'SEGURIDAD: multiples enlaces directos inesperados.'
}

# Habilitar ambas secciones de la GPO.
$Gpo = Get-GPO -Guid $GpoGuid -Domain $DomainName -Server $Pdc -ErrorAction Stop
$Gpo.GpoStatus = 'AllSettingsEnabled'

# ---------------------------------------------------------------------------
# VERIFICACION DE VALORES CLAVE
# ---------------------------------------------------------------------------
Write-Step 'Verificando valores clave almacenados en la GPO'

$Verification = @()

function Add-Verification {
    param(
        [string]$Browser,
        [string]$Key,
        [string]$ValueName,
        $Expected
    )

    try {
        $item = Get-GPRegistryValue `
            -Guid $script:GpoGuid `
            -Domain $script:DomainName `
            -Server $script:Pdc `
            -Key $Key `
            -ValueName $ValueName `
            -ErrorAction Stop

        $actual = $item.Value

        $script:Verification += [pscustomobject]@{
            Browser  = $Browser
            Setting  = $ValueName
            Expected = $Expected
            Actual   = $actual
            OK       = ([string]$actual -eq [string]$Expected)
        }
    }
    catch {
        $script:Verification += [pscustomobject]@{
            Browser  = $Browser
            Setting  = $ValueName
            Expected = $Expected
            Actual   = '<NO ENCONTRADO>'
            OK       = $false
        }
    }
}

Add-Verification -Browser 'Chrome' `
    -Key $ChromeKey `
    -ValueName 'IncognitoModeAvailability' `
    -Expected 1

Add-Verification -Browser 'Chrome' `
    -Key 'HKLM\Software\Policies\Google\Chrome\ClearBrowsingDataOnExitList' `
    -ValueName '1' `
    -Expected 'cached_images_and_files'

Add-Verification -Browser 'Edge' `
    -Key $EdgeKey `
    -ValueName 'InPrivateModeAvailability' `
    -Expected 1

Add-Verification -Browser 'Edge' `
    -Key $EdgeKey `
    -ValueName 'ClearCachedImagesAndFilesOnExit' `
    -Expected 1

Add-Verification -Browser 'Firefox' `
    -Key $FirefoxSanitizeKey `
    -ValueName 'Cache' `
    -Expected 1

Add-Verification -Browser 'Firefox' `
    -Key $FirefoxSanitizeKey `
    -ValueName 'Cookies' `
    -Expected 0

$Verification | Format-Table -AutoSize

if (@($Verification | Where-Object { -not $_.OK }).Count -gt 0) {
    throw 'Validacion interna fallida: uno o mas valores clave no coinciden.'
}

# ---------------------------------------------------------------------------
# REPORTE POST
# ---------------------------------------------------------------------------
Write-Step 'Generando reportes POST'

Get-GPOReport -Guid $GpoGuid -Domain $DomainName -Server $Pdc `
    -ReportType Xml -Path (Join-Path $BackupPath 'POST_GPO_Report.xml')

Get-GPOReport -Guid $GpoGuid -Domain $DomainName -Server $Pdc `
    -ReportType Html -Path (Join-Path $BackupPath 'POST_GPO_Report.html')

# ---------------------------------------------------------------------------
# REPLICACION AD OPCIONAL
# ---------------------------------------------------------------------------
if ($SyncReplication) {
    Write-Step 'Forzando replicacion AD'

    if (Get-Command repadmin.exe -ErrorAction SilentlyContinue) {
        & repadmin.exe /syncall $Pdc /AdeP

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "repadmin /syncall termino con codigo $LASTEXITCODE."
        }
    }
    else {
        Write-Warning 'repadmin.exe no esta disponible.'
    }
}

# ---------------------------------------------------------------------------
# SYSVOL
# ---------------------------------------------------------------------------
Write-Step 'Comprobando SYSVOL en todos los DC'

$DcChecks = foreach ($dc in (Get-ADDomainController -Filter * -Server $Pdc | Sort-Object HostName)) {
    $sysvolPath = "\\$($dc.HostName)\SYSVOL\$DomainName\Policies\{$($GpoGuid.ToString().ToUpper())}"

    [pscustomobject]@{
        DC          = $dc.HostName
        IPv4Address = $dc.IPv4Address
        Present     = [bool](Test-Path $sysvolPath)
        Path        = $sysvolPath
    }
}

$DcChecks | Format-Table DC,IPv4Address,Present -AutoSize
$DcChecks | Export-Csv `
    -Path (Join-Path $BackupPath 'SYSVOL_DC_Check.csv') `
    -NoTypeInformation `
    -Encoding UTF8

if (@($DcChecks | Where-Object { -not $_.Present }).Count -gt 0) {
    Write-Warning 'La GPO aun no aparece en SYSVOL de todos los DC. Revise DFSR antes de despliegue masivo.'
}

# ---------------------------------------------------------------------------
# GPUPDATE LOCAL OPCIONAL
# ---------------------------------------------------------------------------
if ($RefreshThisComputer) {
    Write-Step 'Ejecutando gpupdate local'

    & gpupdate.exe /target:computer /force

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "gpupdate termino con codigo $LASTEXITCODE."
    }
}

# ---------------------------------------------------------------------------
# RESUMEN
# ---------------------------------------------------------------------------
$FinalGpo = Get-GPO -Guid $GpoGuid -Domain $DomainName -Server $Pdc
$FinalInheritance = Get-GPInheritance -Target $DomainDn -Domain $DomainName -Server $Pdc
$FinalLink = @($FinalInheritance.GpoLinks | Where-Object { $_.GpoId -eq $GpoGuid })

$Summary = [pscustomobject]@{
    Domain               = $DomainName
    ExecutedFrom         = $env:COMPUTERNAME
    PDCEmulator          = $Pdc
    GpoName              = $FinalGpo.DisplayName
    GpoGuid              = $FinalGpo.Id
    GpoStatus            = $FinalGpo.GpoStatus
    LinkTarget           = $DomainDn
    LinkOrder            = if ($FinalLink.Count -eq 1) { $FinalLink[0].Order } else { '<ERROR>' }
    LinkEnabled          = if ($FinalLink.Count -eq 1) { $FinalLink[0].Enabled } else { '<ERROR>' }
    LinkEnforced         = if ($FinalLink.Count -eq 1) { $FinalLink[0].Enforced } else { '<ERROR>' }
    ChromeBlockPatterns  = $ChromiumBlockedPatterns.Count
    EdgeBlockPatterns    = $ChromiumBlockedPatterns.Count
    FirefoxBlockPatterns = $FirefoxBlockedPatterns.Count
    CacheCleanupOnExit   = 'Chrome, Edge, Firefox - SOLO CACHE'
    CookiesPreserved     = $true
    SessionsPreserved    = $true
    HistoryPreserved     = $true
    PasswordsPreserved   = $true
    ExtensionAllowOnly   = $EnforceExtensionAllowlistOnly.IsPresent
    BackupPath           = $BackupPath
}

Write-Step 'RESULTADO FINAL'
$Summary | Format-List

$Summary | Export-Csv `
    -Path (Join-Path $BackupPath 'Deployment_Summary.csv') `
    -NoTypeInformation `
    -Encoding UTF8

Write-Host "`nGPO COMPLETA aplicada correctamente." -ForegroundColor Green
Write-Host "Backup/reportes: $BackupPath" -ForegroundColor Green
Write-Host ""
Write-Host "Prueba recomendada en UN cliente piloto:" -ForegroundColor Cyan
Write-Host "  gpupdate /force"
Write-Host "  gpresult /scope computer /r"
Write-Host "  Chrome  : chrome://policy"
Write-Host "  Edge    : edge://policy"
Write-Host "  Firefox : about:policies"
Write-Host ""
Write-Host "Cache al cerrar:" -ForegroundColor Cyan
Write-Host "  Chrome  -> cached_images_and_files"
Write-Host "  Edge    -> ClearCachedImagesAndFilesOnExit = 1"
Write-Host "  Firefox -> Cache=1; Cookies/History/Sessions/FormData/SiteSettings=0"

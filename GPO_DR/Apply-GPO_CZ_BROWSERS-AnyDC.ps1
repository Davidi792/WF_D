#requires -Version 5.1
#requires -RunAsAdministrator
#requires -Modules ActiveDirectory,GroupPolicy

<#+
.SYNOPSIS
  Crea o actualiza de forma idempotente la GPO GPO_CZ_BROWSERS desde cualquier DC del dominio.

.DESCRIPTION
  - Detecta el dominio y valida que sea corp.callzilla.net.
  - Puede ejecutarse en AZDOMAIN2, AZDOMAIN3 o cualquier DC futuro con RSAT/GroupPolicy.
  - Si la GPO existe, realiza backup y la actualiza en sitio.
  - Si no existe, la crea y la enlaza a la raiz del dominio.
  - Consolida Chrome, Edge y Firefox en Computer Configuration (HKLM).
  - Usa User Configuration solo para limpiar valores HKCU heredados de la GPO anterior.
  - Mantiene el enlace en orden 4, habilitado y no enforced por defecto.
  - Opcionalmente fuerza replicacion AD con repadmin y/o gpupdate en el equipo desde el que se ejecuta.

.NOTES
  Dominio objetivo: corp.callzilla.net
  GPO canonica:    GPO_CZ_BROWSERS
#>

[CmdletBinding()]
param(
    [ValidateSet('Deploy','Audit')]
    [string]$Mode = 'Deploy',

    [string]$DomainName = 'corp.callzilla.net',
    [string]$GpoName = 'GPO_CZ_BROWSERS',
    [int]$LinkOrder = 4,
    [string]$BackupRoot = 'C:\GPO_Backups\GPO_CZ_BROWSERS',

    [switch]$EnforceExtensionAllowlistOnly,
    [switch]$SyncReplication,
    [switch]$RefreshThisComputer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step {
    param([Parameter(Mandatory)][string]$Message)
    Write-Host "`n=== $Message ===" -ForegroundColor Cyan
}

function Set-GpoValue {
    param(
        [Parameter(Mandatory)][guid]$GpoGuid,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string]$ValueName,
        [Parameter(Mandatory)]$Value,
        [Parameter(Mandatory)][ValidateSet('String','DWord','ExpandString','MultiString','QWord','Binary')][string]$Type
    )

    Set-GPRegistryValue -Guid $GpoGuid -Domain $Domain -Key $Key `
        -ValueName $ValueName -Value $Value -Type $Type | Out-Null
}

function Disable-GpoValue {
    param(
        [Parameter(Mandatory)][guid]$GpoGuid,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Key,
        [string]$ValueName
    )

    $params = @{
        Guid    = $GpoGuid
        Domain  = $Domain
        Key     = $Key
        Disable = $true
    }
    if ($PSBoundParameters.ContainsKey('ValueName')) {
        $params.ValueName = $ValueName
    }
    Set-GPRegistryValue @params | Out-Null
}

function Set-GpoStringList {
    param(
        [Parameter(Mandatory)][guid]$GpoGuid,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][string[]]$Values
    )

    # Limpia entradas anteriores de la lista para que no sobrevivan indices viejos.
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $Domain -Key $Key

    $i = 1
    foreach ($item in ($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        Set-GPRegistryValue -Guid $GpoGuid -Domain $Domain -Key $Key `
            -ValueName ([string]$i) -Value $item.Trim() -Type String | Out-Null
        $i++
    }
}

# -----------------------------------------------------------------------------
# Datos corregidos de la politica
# -----------------------------------------------------------------------------
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

# -----------------------------------------------------------------------------
# Validacion de entorno
# -----------------------------------------------------------------------------
Write-Step 'Validando dominio, modulos y controlador de dominio'
Import-Module ActiveDirectory -ErrorAction Stop
Import-Module GroupPolicy -ErrorAction Stop

$Domain = Get-ADDomain -Identity $DomainName
if ($Domain.DNSRoot -ne $DomainName) {
    throw "Dominio actual '$($Domain.DNSRoot)' no coincide con '$DomainName'."
}

$DomainDn = $Domain.DistinguishedName
$Pdc = $Domain.PDCEmulator
$LocalDc = Get-ADDomainController -Identity $env:COMPUTERNAME -ErrorAction SilentlyContinue

Write-Host "Dominio            : $($Domain.DNSRoot)"
Write-Host "DN                  : $DomainDn"
Write-Host "PDC Emulator        : $Pdc"
if ($null -ne $LocalDc) {
    Write-Host "Ejecucion desde DC  : $($LocalDc.HostName) [$($LocalDc.IPv4Address)]"
} else {
    Write-Warning "El equipo $env:COMPUTERNAME no aparece como DC. Se continuara si tiene RSAT y conectividad al dominio."
}

# -----------------------------------------------------------------------------
# Localizar o crear GPO
# -----------------------------------------------------------------------------
$Gpo = Get-GPO -Name $GpoName -Domain $DomainName -ErrorAction SilentlyContinue
$Exists = ($null -ne $Gpo)
$TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$BackupPath = Join-Path $BackupRoot $TimeStamp

if ($Exists) {
    Write-Host "GPO encontrada      : $($Gpo.DisplayName)"
    Write-Host "GUID                : $($Gpo.Id)"
    Write-Host "Status              : $($Gpo.GpoStatus)"
} else {
    Write-Warning "La GPO '$GpoName' no existe y sera creada en modo Deploy."
}

$Inheritance = Get-GPInheritance -Target $DomainDn -Domain $DomainName
$ExistingLinks = @()
if ($Exists) {
    $ExistingLinks = @($Inheritance.GpoLinks | Where-Object { $_.GpoId -eq $Gpo.Id })
}

if ($ExistingLinks.Count -gt 1) {
    throw "La GPO '$GpoName' tiene mas de un enlace directo al dominio. Revise manualmente antes de continuar."
}

if ($ExistingLinks.Count -eq 1) {
    Write-Host "Link target         : $DomainDn"
    Write-Host "Link order          : $($ExistingLinks[0].Order)"
    Write-Host "Link enabled        : $($ExistingLinks[0].Enabled)"
    Write-Host "Link enforced       : $($ExistingLinks[0].Enforced)"
} else {
    Write-Host "Link target         : $DomainDn (se creara)"
    Write-Host "Link order          : $LinkOrder"
    Write-Host "Link enabled        : True"
    Write-Host "Link enforced       : False"
}

Write-Host "Extension allow-only: $($EnforceExtensionAllowlistOnly.IsPresent)"

if ($Mode -eq 'Audit') {
    Write-Warning 'AUDIT: no se realizaron cambios.'
    return
}

# -----------------------------------------------------------------------------
# Backup / creacion
# -----------------------------------------------------------------------------
if ($Exists) {
    Write-Step 'Creando backup y reporte PRE de la GPO activa'
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    Backup-GPO -Guid $Gpo.Id -Domain $DomainName -Path $BackupPath | Out-Null
    Get-GPOReport -Guid $Gpo.Id -Domain $DomainName -ReportType Xml -Path (Join-Path $BackupPath 'PRE_GPO_Report.xml')
    Get-GPOReport -Guid $Gpo.Id -Domain $DomainName -ReportType Html -Path (Join-Path $BackupPath 'PRE_GPO_Report.html')
} else {
    Write-Step 'Creando nueva GPO'
    New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
    $Gpo = New-GPO -Name $GpoName -Domain $DomainName -Comment 'Browser hardening: Chrome, Edge and Firefox. Managed by Apply-GPO_CZ_BROWSERS-AnyDC.ps1'
    $Exists = $true
}

$GpoGuid = $Gpo.Id

# -----------------------------------------------------------------------------
# Limpieza de USER scope heredado
# -----------------------------------------------------------------------------
Write-Step 'Limpiando configuracion User heredada (HKCU)'
$ChromeUserValuesToDelete = @(
    'SigninAllowed','IncognitoModeAvailability','DefaultSearchProviderKeyword',
    'DefaultSearchProviderName','DefaultSearchProviderNewTabURL',
    'DefaultSearchProviderSearchURL','DefaultSearchProviderSuggestURL',
    'DefaultSearchProviderEnabled','AmbientAuthenticationInPrivateModesEnabled',
    'BrowserGuestModeEnabled','BrowserGuestModeEnforced'
)
foreach ($valueName in $ChromeUserValuesToDelete) {
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKCU\Software\Policies\Google\Chrome' -ValueName $valueName
}
foreach ($key in @(
    'HKCU\Software\Policies\Google\Chrome\DefaultSearchProviderAlternateURLs',
    'HKCU\Software\Policies\Google\Chrome\ExtensionInstallAllowlist',
    'HKCU\Software\Policies\Google\Chrome\ExtensionInstallForcelist',
    'HKCU\Software\Policies\Google\Chrome\RestoreOnStartupURLs',
    'HKCU\Software\Policies\Google\Chrome\URLBlocklist'
)) {
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $key
}

$EdgeUserValuesToDelete = @(
    'InPrivateModeAvailability','HomepageLocation','NewTabPageLocation','RestoreOnStartup',
    'ClearCachedImagesAndFilesOnExit','ClearBrowsingDataOnExit'
)
foreach ($valueName in $EdgeUserValuesToDelete) {
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKCU\Software\Policies\Microsoft\Edge' -ValueName $valueName
}
foreach ($key in @(
    'HKCU\Software\Policies\Microsoft\Edge\ExtensionAllowedTypes',
    'HKCU\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist',
    'HKCU\Software\Policies\Microsoft\Edge\URLBlocklist'
)) {
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $key
}

Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKCU\Software\Policies\Mozilla\Firefox' -ValueName 'DisablePrivateBrowsing'
foreach ($key in @(
    'HKCU\Software\Policies\Mozilla\Firefox\Extensions\Install',
    'HKCU\Software\Policies\Mozilla\Firefox\Homepage',
    'HKCU\Software\Policies\Mozilla\Firefox\WebsiteFilter\Block'
)) {
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $key
}

# -----------------------------------------------------------------------------
# CHROME - Computer Configuration
# -----------------------------------------------------------------------------
Write-Step 'Aplicando Chrome en Computer Configuration'
$ChromeKey = 'HKLM\Software\Policies\Google\Chrome'
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'BrowserGuestModeEnabled' -Value 0 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'BrowserGuestModeEnforced' -Value 0 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'IncognitoModeAvailability' -Value 1 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'HomepageLocation' -Value 'https://www.google.com/' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'NewTabPageLocation' -Value 'https://www.callzilla.cx/' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'RestoreOnStartup' -Value 4 -Type DWord
Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Google\Chrome\RestoreOnStartupURLs' -Values @('https://www.google.com/')

Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'DefaultSearchProviderEnabled' -Value 1 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'DefaultSearchProviderName' -Value 'Callzilla Safe Search' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'DefaultSearchProviderKeyword' -Value '@webonly' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'DefaultSearchProviderSearchURL' -Value 'https://www.google.com/search?q={searchTerms}&udm=14' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'DefaultSearchProviderSuggestURL' -Value 'https://www.google.com/complete/search?output=chrome&q={searchTerms}' -Type String
Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $ChromeKey -ValueName 'DefaultSearchProviderNewTabURL'
Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Google\Chrome\DefaultSearchProviderAlternateURLs'

Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Google\Chrome\URLBlocklist' -Values $ChromiumBlockedPatterns
Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallAllowlist' -Values $ChromeExtensionAllowlist
Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallForcelist' -Values $ChromeExtensionForcelist
if ($EnforceExtensionAllowlistOnly) {
    Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallBlocklist' -Values @('*')
} else {
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Google\Chrome\ExtensionInstallBlocklist'
}

# -----------------------------------------------------------------------------
# EDGE - Computer Configuration
# -----------------------------------------------------------------------------
Write-Step 'Aplicando Microsoft Edge en Computer Configuration'
$EdgeKey = 'HKLM\Software\Policies\Microsoft\Edge'
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $EdgeKey -ValueName 'BrowserGuestModeEnabled' -Value 0 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $EdgeKey -ValueName 'InPrivateModeAvailability' -Value 1 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $EdgeKey -ValueName 'HomepageLocation' -Value 'https://www.google.com/' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $EdgeKey -ValueName 'NewTabPageLocation' -Value 'https://www.google.com/' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $EdgeKey -ValueName 'RestoreOnStartup' -Value 5 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $EdgeKey -ValueName 'ClearBrowsingDataOnExit' -Value 1 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $EdgeKey -ValueName 'ClearCachedImagesAndFilesOnExit' -Value 1 -Type DWord
Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Microsoft\Edge\URLBlocklist' -Values $ChromiumBlockedPatterns
Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallAllowlist' -Values $EdgeExtensionAllowlist
if ($EnforceExtensionAllowlistOnly) {
    Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist' -Values @('*')
} else {
    Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Microsoft\Edge\ExtensionInstallBlocklist'
}
Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Microsoft\MicrosoftEdge\Main' -ValueName 'AllowInPrivate'
Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Microsoft\MicrosoftEdge\Internet Settings' -ValueName 'HomeButtonURL'

# -----------------------------------------------------------------------------
# FIREFOX - Computer Configuration
# -----------------------------------------------------------------------------
Write-Step 'Aplicando Firefox en Computer Configuration'
$FirefoxKey = 'HKLM\Software\Policies\Mozilla\Firefox'
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $FirefoxKey -ValueName 'PrivateBrowsingModeAvailability' -Value 1 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $FirefoxKey -ValueName 'DisablePrivateBrowsing' -Value 1 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Mozilla\Firefox\Homepage' -ValueName 'URL' -Value 'https://www.google.com/' -Type String
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Mozilla\Firefox\Homepage' -ValueName 'Locked' -Value 1 -Type DWord
Set-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Mozilla\Firefox\Homepage' -ValueName 'StartPage' -Value 'homepage-locked' -Type String
Set-GpoStringList -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Mozilla\Firefox\WebsiteFilter\Block' -Values $FirefoxBlockedPatterns
Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key $FirefoxKey -ValueName 'DisableFirefoxAccounts'
Disable-GpoValue -GpoGuid $GpoGuid -Domain $DomainName -Key 'HKLM\Software\Policies\Mozilla\Firefox\Extensions\Install'

# -----------------------------------------------------------------------------
# Enlace al dominio
# -----------------------------------------------------------------------------
Write-Step 'Validando/creando enlace de la GPO al dominio'
$Inheritance = Get-GPInheritance -Target $DomainDn -Domain $DomainName
$Links = @($Inheritance.GpoLinks | Where-Object { $_.GpoId -eq $GpoGuid })

if ($Links.Count -eq 0) {
    New-GPLink -Guid $GpoGuid -Domain $DomainName -Target $DomainDn -LinkEnabled Yes -Enforced No -Order $LinkOrder | Out-Null
} elseif ($Links.Count -eq 1) {
    Set-GPLink -Guid $GpoGuid -Domain $DomainName -Target $DomainDn -LinkEnabled Yes -Enforced No -Order $LinkOrder | Out-Null
} else {
    throw "La GPO tiene multiples enlaces directos inesperados al dominio."
}

# Asegurar que la GPO este habilitada.
$Gpo = Get-GPO -Guid $GpoGuid -Domain $DomainName
$Gpo.GpoStatus = 'AllSettingsEnabled'

# -----------------------------------------------------------------------------
# Reporte POST
# -----------------------------------------------------------------------------
Write-Step 'Generando reporte POST y validacion final'
Get-GPOReport -Guid $GpoGuid -Domain $DomainName -ReportType Xml -Path (Join-Path $BackupPath 'POST_GPO_Report.xml')
Get-GPOReport -Guid $GpoGuid -Domain $DomainName -ReportType Html -Path (Join-Path $BackupPath 'POST_GPO_Report.html')

$FinalInheritance = Get-GPInheritance -Target $DomainDn -Domain $DomainName
$FinalLink = @($FinalInheritance.GpoLinks | Where-Object { $_.GpoId -eq $GpoGuid })
if ($FinalLink.Count -ne 1) {
    throw 'Validacion final fallida: la GPO no tiene exactamente un enlace directo a la raiz del dominio.'
}

# -----------------------------------------------------------------------------
# Replicacion AD opcional
# -----------------------------------------------------------------------------
if ($SyncReplication) {
    Write-Step 'Forzando replicacion de Active Directory'
    $repadmin = Get-Command repadmin.exe -ErrorAction SilentlyContinue
    if ($null -eq $repadmin) {
        Write-Warning 'repadmin.exe no esta disponible en este equipo.'
    } else {
        & repadmin.exe /syncall /AdeP
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "repadmin /syncall finalizo con codigo $LASTEXITCODE. Revise la salida anterior."
        }
    }
}

# -----------------------------------------------------------------------------
# Validacion de presencia del GPT en SYSVOL de todos los DC
# -----------------------------------------------------------------------------
Write-Step 'Comprobando presencia de la GPO en SYSVOL de los DC'
$DcChecks = foreach ($dc in (Get-ADDomainController -Filter * | Sort-Object HostName)) {
    $Path = "\\$($dc.HostName)\SYSVOL\$DomainName\Policies\{$($GpoGuid.ToString().ToUpper())}"
    [pscustomobject]@{
        DC          = $dc.HostName
        IPv4Address = $dc.IPv4Address
        SysvolPath  = $Path
        Present     = [bool](Test-Path $Path)
    }
}
$DcChecks | Format-Table DC,IPv4Address,Present -AutoSize
$DcChecks | Export-Csv -Path (Join-Path $BackupPath 'SYSVOL_DC_Check.csv') -NoTypeInformation -Encoding UTF8

if (@($DcChecks | Where-Object { -not $_.Present }).Count -gt 0) {
    Write-Warning 'La GPO aun no aparece en SYSVOL de todos los DC. AD puede estar correcto mientras DFSR aun replica SYSVOL.'
}

# -----------------------------------------------------------------------------
# gpupdate opcional solo en el equipo desde el que se ejecuta
# -----------------------------------------------------------------------------
if ($RefreshThisComputer) {
    Write-Step 'Ejecutando gpupdate /target:computer /force en este equipo'
    & gpupdate.exe /target:computer /force
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "gpupdate finalizo con codigo $LASTEXITCODE."
    }
}

$FinalGpo = Get-GPO -Guid $GpoGuid -Domain $DomainName
$Summary = [pscustomobject]@{
    Domain              = $DomainName
    ExecutedFrom        = $env:COMPUTERNAME
    PDCEmulator         = $Pdc
    GpoName             = $FinalGpo.DisplayName
    GpoGuid             = $FinalGpo.Id
    GpoStatus           = $FinalGpo.GpoStatus
    LinkTarget          = $DomainDn
    LinkOrder           = $FinalLink[0].Order
    LinkEnabled         = $FinalLink[0].Enabled
    LinkEnforced        = $FinalLink[0].Enforced
    ChromeBlockPatterns = $ChromiumBlockedPatterns.Count
    EdgeBlockPatterns   = $ChromiumBlockedPatterns.Count
    FirefoxBlockPatterns= $FirefoxBlockedPatterns.Count
    ExtensionAllowOnly  = $EnforceExtensionAllowlistOnly.IsPresent
    BackupPath          = $BackupPath
}

Write-Step 'Resultado final'
$Summary | Format-List
$Summary | Export-Csv -Path (Join-Path $BackupPath 'Deployment_Summary.csv') -NoTypeInformation -Encoding UTF8

Write-Host "`nGPO aplicada/actualizada correctamente." -ForegroundColor Green
Write-Host "Backup y reportes: $BackupPath" -ForegroundColor Green
Write-Host "`nPrueba recomendada en un cliente piloto:" -ForegroundColor Cyan
Write-Host '  gpupdate /force'
Write-Host '  gpresult /scope computer /r'
Write-Host '  Chrome:  chrome://policy'
Write-Host '  Edge:    edge://policy'
Write-Host '  Firefox: about:policies'

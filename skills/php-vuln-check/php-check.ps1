# PHP check for CVE-2026-109618 / CVE-2026-109619 (fixed on 2026-10-21) - Incerto LLC
# Finds where PHP runs on this Windows machine and whether it needs updating.
# Read-only: it does not change, delete or send anything. No full-disk scan.
# Usage: open PowerShell, paste all of this, press Enter, then send the output to Incerto.

$ErrorActionPreference = 'SilentlyContinue'
$script:fixed = @{ '8.2' = 35; '8.3' = 36; '8.4' = 27; '8.5' = 12 }
function Judge([string]$v) {
  $m = [regex]::Match($v, '(\d+)\.(\d+)\.(\d+)')
  if (-not $m.Success) { return 'cannot judge' }
  $mm = $m.Groups[1].Value + '.' + $m.Groups[2].Value
  $patch = [int]$m.Groups[3].Value
  if (-not $script:fixed.ContainsKey($mm)) { return 'END OF LIFE: no fix will be released. Upgrade to a supported version (8.2.35 or later)' }
  $f = [int]$script:fixed[$mm]
  if ($patch -ge $f) { return 'FIXED' }
  return ('AFFECTED: update to {0}.{1} or later' -f $mm, $f)
}
function Section($t) { Write-Output ''; Write-Output "--- $t ---" }
Write-Output ("=== PHP check {0} / {1} / {2} / user={3} ===" -f (Get-Date -Format 'yyyy-MM-dd HH:mm'), $env:COMPUTERNAME, [Environment]::OSVersion.VersionString, $env:USERNAME)
Write-Output 'Fixed versions: 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 (older are affected; 8.1 and older get no fix)'

# Places where PHP is usually installed (drive roots + Program Files etc.)
$bases = @()
foreach ($d in @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Root })) {
  foreach ($n in 'xampp', 'php', 'wamp', 'wamp64', 'laragon', 'MAMP', 'inetpub', 'Apache24', 'nginx', 'www', 'htdocs', 'server') { $bases += (Join-Path $d $n) }
}
$bases += @($env:ProgramFiles, ${env:ProgramFiles(x86)})
if ($env:ProgramData) { $bases += (Join-Path $env:ProgramData 'chocolatey\lib') }
if ($env:USERPROFILE) { $bases += (Join-Path $env:USERPROFILE 'scoop\apps') }
$bases = @($bases | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)

# -------------------------------------------------------------
Section '1. PHP executables, versions and verdict'
$exe = @()
$exe += @(Get-Command php.exe, php-cgi.exe -All | ForEach-Object { $_.Source })
foreach ($b in $bases) {
  foreach ($name in 'php.exe', 'php-cgi.exe') {
    $exe += @(Get-ChildItem -Path $b -Recurse -Depth 4 -File -Filter $name | ForEach-Object { $_.FullName })
  }
}
$exe += @(Get-Process | Where-Object { $_.ProcessName -match '^php(-cgi)?$' } | ForEach-Object { $_.Path })
$appcmd = if ($env:windir) { Join-Path $env:windir 'system32\inetsrv\appcmd.exe' } else { $null }
if ($appcmd -and (Test-Path $appcmd)) {
  $exe += @(& $appcmd list config -section:system.webServer/fastCgi | Select-String -Pattern 'fullPath="([^"]+)"' -AllMatches |
            ForEach-Object { $_.Matches } | ForEach-Object { $_.Groups[1].Value })
}
$exe = @($exe | Where-Object { $_ -and (Test-Path $_) } | Sort-Object -Unique)
if ($exe.Count -eq 0) { Write-Output 'No PHP found in the usual places' }
foreach ($p in $exe) {
  # Read the version from the file's version info first (no need to run PHP); fall back to "php -v"
  $line = [string](Get-Item -LiteralPath $p).VersionInfo.ProductVersion
  if (-not $line) { $line = [string](& $p -v 2>$null | Select-Object -First 1) }
  $verdict = Judge $line
  Write-Output "$p : $line"
  Write-Output "    -> $verdict"
}

# -------------------------------------------------------------
Section '2. How PHP is served (every setup needs the update)'
foreach ($b in $bases) {
  Get-ChildItem -Path $b -Recurse -Depth 4 -File -Filter 'httpd.conf' | ForEach-Object {
    $m = Select-String -Path $_.FullName -Pattern '^\s*LoadModule\s+php' | Select-Object -First 1
    if ($m) { Write-Output ("Apache with PHP module (mod_php): {0}  [{1}]" -f $_.FullName, $m.Line.Trim()) }
  }
}
if ($appcmd -and (Test-Path $appcmd)) {
  & $appcmd list config -section:system.webServer/handlers | Select-String -Pattern 'php' | ForEach-Object { Write-Output ('IIS handler: ' + $_.Line.Trim()) }
} else { Write-Output 'IIS: not installed' }
if (Get-Command Get-CimInstance) {
  Get-CimInstance Win32_Service | Where-Object { $_.PathName -match 'php|httpd|apache|nginx' } |
    ForEach-Object { Write-Output ('Service: {0} [{1}] {2}' -f $_.Name, $_.State, $_.PathName) }
}
if (Get-Command Get-NetTCPConnection) {
  Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -in 80, 443, 8000, 8080, 8443, 8888 } |
    ForEach-Object { $pr = Get-Process -Id $_.OwningProcess; Write-Output ('Listening {0}:{1}  {2}  {3}' -f $_.LocalAddress, $_.LocalPort, $pr.ProcessName, $pr.Path) }
}

# -------------------------------------------------------------
Section '3. Mitigation settings named by the advisory (values seen by php.exe; a stopgap, not a fix)'
foreach ($p in ($exe | Where-Object { $_ -match '\\php\.exe$' })) {
  Write-Output "[$p]"
  & $p -i 2>$null | Select-String -Pattern '^(Loaded Configuration File|session\.upload_progress\.enabled|fatal_error_backtraces) ' |
    ForEach-Object { Write-Output ('    ' + $_.Line) }
}
Write-Output '(If session.upload_progress.enabled is On, turning it Off until you update is one official mitigation.'
Write-Output ' Ask whoever runs that system before changing it; the web server must be restarted.)'

# -------------------------------------------------------------
Section '4. PHP applications found (WordPress, phpMyAdmin, EC-CUBE, Moodle, MediaWiki, Laravel)'
# Web folders only (Program Files is skipped here to keep this fast)
$webBases = @($bases | Where-Object { $_ -ne $env:ProgramFiles -and $_ -ne ${env:ProgramFiles(x86)} })
foreach ($b in $webBases) {
  foreach ($name in 'version.php', 'Constant.php', 'moodlelib.php', 'LocalSettings.php', 'artisan', 'config.inc.php') {
  Get-ChildItem -Path $b -Recurse -Depth 6 -File -Filter $name |
  ForEach-Object {
    $f = $_.FullName
    if ($f -match '\\wp-includes\\version\.php$') {
      $v = (Select-String -Path $f -Pattern "^\`$wp_version\s*=\s*'([^']+)'" | Select-Object -First 1).Matches.Groups[1].Value
      Write-Output ("WordPress {0}: {1}" -f $v, (Split-Path (Split-Path $f -Parent) -Parent))
    }
    elseif ($f -match '\\src\\Eccube\\Common\\Constant\.php$') { Write-Output "EC-CUBE: $f" }
    elseif ($f -match '\\lib\\moodlelib\.php$') { Write-Output "Moodle: $f" }
    elseif ($f -match '\\LocalSettings\.php$') { Write-Output "MediaWiki: $f" }
    elseif ($f -match '\\artisan$') { Write-Output "Laravel?: $f" }
    elseif ($f -match '(?i)phpmyadmin|\\pma\\') { Write-Output "phpMyAdmin: $f" }
  }
  }
}
Write-Output '(These are fixed by updating PHP in section 1; updating the application itself is a separate matter.)'

Write-Output ''
Write-Output '=== Done. Please send this output to Incerto (nothing was changed) ==='

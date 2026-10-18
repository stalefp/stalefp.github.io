# Install/verify the newest official Windows stable build of Microsoft Edge or Brave, for capture_brand.py.
#   pwsh capture/install_brand_win.ps1 edge|brave <workdir>
# Edge:  the runner image ships Edge; if Microsoft's update API (edgeupdates.microsoft.com) lists a newer Stable x64 build,
#        its MSI is downloaded, checked against the SHA256 the API publishes and against a Microsoft Authenticode signature,
#        and installed. msedge.exe itself must carry a valid Microsoft Corporation signature.
# Brave: BraveBrowserStandaloneSilentSetup.exe from the newest non-prerelease GitHub release of brave/brave-browser,
#        checked against the release's .sha256 file and a valid "Brave Software, Inc." Authenticode signature, then installed.
# Prints KEY=VALUE lines (BRAND_BIN, BRAND_PKG_VERSION, BRAND_REPO, BRAND_DEB_SHA256, BRAND_KEY), same as install_brand_deb.sh.
param([Parameter(Mandatory)][ValidateSet("edge","brave")][string]$Brand, [string]$Work = $env:RUNNER_TEMP)
$ErrorActionPreference = "Stop"; $ProgressPreference = "SilentlyContinue"
New-Item -ItemType Directory -Force -Path $Work | Out-Null
function Need-Signature($path, $subject) {
  $s = Get-AuthenticodeSignature -LiteralPath $path
  if ($s.Status -ne "Valid" -or $s.SignerCertificate.Subject -notmatch [regex]::Escape($subject)) { throw "bad signature on ${path}: $($s.Status) $($s.SignerCertificate.Subject)" }
  return $s.SignerCertificate.Subject
}
function Ver($p) { if (Test-Path -LiteralPath $p) { (Get-Item -LiteralPath $p).VersionInfo.ProductVersion } else { $null } }
if ($Brand -eq "edge") {
  $exe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
  if (-not (Test-Path $exe)) { $exe = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" }
  $have = Ver $exe
  # Invoke-RestMethod hands back the JSON array as one pipeline object; unroll it before filtering
  $prods = @(Invoke-RestMethod "https://edgeupdates.microsoft.com/api/products") | ForEach-Object { $_ }
  $rel = ($prods | Where-Object { $_.Product -eq "Stable" }).Releases |
    Where-Object { $_.Platform -eq "Windows" -and $_.Architecture -eq "x64" } | Sort-Object { [version]$_.ProductVersion } -Descending | Select-Object -First 1
  $src = "preinstalled on the runner image"; $sha = $null
  [Console]::Error.WriteLine("Edge preinstalled: $have, newest Stable x64 per edgeupdates API: $($rel.ProductVersion)")
  if (-not $rel) { throw "edgeupdates API returned no Stable Windows x64 release" }
  if ($rel -and (-not $have -or [version]$have -lt [version]$rel.ProductVersion)) {
    $art = $rel.Artifacts | Where-Object ArtifactName -eq "msi" | Select-Object -First 1
    $msi = Join-Path $Work "edge.msi"
    Invoke-WebRequest -Uri $art.Location -OutFile $msi
    $sha = (Get-FileHash -Algorithm SHA256 $msi).Hash.ToLower()
    if ($art.HashAlgorithm -ne "SHA256" -or $sha -ne $art.Hash.ToLower()) { throw "Edge MSI SHA256 mismatch ($sha vs $($art.Hash))" }
    Need-Signature $msi "Microsoft Corporation" | Out-Null
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart" -Wait -PassThru
    [Console]::Error.WriteLine("Edge MSI exit code $($p.ExitCode)")
    $src = "edgeupdates.microsoft.com Stable x64 MSI"
    $exe = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
    if (-not (Test-Path $exe)) { $exe = "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe" }
  }
  $key = Need-Signature $exe "Microsoft Corporation"
} else {
  $h = @{ "User-Agent" = "stalefp-capture" }; if ($env:GITHUB_TOKEN) { $h["Authorization"] = "Bearer $env:GITHUB_TOKEN" }
  $rel = Invoke-RestMethod -Headers $h "https://api.github.com/repos/brave/brave-browser/releases/latest"
  if ($rel.prerelease -or $rel.name -notmatch "^Release ") { throw "latest brave-browser release is not a Release-channel build: $($rel.name)" }
  $asset = $rel.assets | Where-Object name -eq "BraveBrowserStandaloneSilentSetup.exe"
  $sumA = $rel.assets | Where-Object name -eq "BraveBrowserStandaloneSilentSetup.exe.sha256"
  $setup = Join-Path $Work "brave-setup.exe"
  Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $setup
  $sumF = Join-Path $Work "brave-setup.sha256"
  Invoke-WebRequest -Uri $sumA.browser_download_url -OutFile $sumF   # served as octet-stream, so read it from disk as text
  $want = (Get-Content -Raw -LiteralPath $sumF).Trim().Split(" ")[0].ToLower()
  $sha = (Get-FileHash -Algorithm SHA256 $setup).Hash.ToLower()
  if ($sha -ne $want) { throw "Brave installer SHA256 mismatch ($sha vs $want)" }
  Need-Signature $setup "Brave Software" | Out-Null
  Start-Process $setup -Wait | Out-Null
  $cands = @("$env:ProgramFiles\BraveSoftware\Brave-Browser\Application\brave.exe", "${env:ProgramFiles(x86)}\BraveSoftware\Brave-Browser\Application\brave.exe",
             "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\Application\brave.exe")
  $exe = $null
  for ($i = 0; $i -lt 90 -and -not $exe; $i++) { $exe = $cands | Where-Object { Test-Path $_ } | Select-Object -First 1; if (-not $exe) { Start-Sleep 2 } }
  if (-not $exe) { throw "brave.exe not found after install" }
  Start-Sleep 5; Get-Process brave -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  $src = "github.com/brave/brave-browser $($rel.tag_name) BraveBrowserStandaloneSilentSetup.exe"
  $key = Need-Signature $exe "Brave Software"
}
$v = (Get-Item -LiteralPath $exe).VersionInfo
[Console]::Error.WriteLine("$Brand -> $exe $($v.ProductName) $($v.ProductVersion)")
"BRAND_BIN=$exe"
"BRAND_PKG_VERSION=$($v.ProductVersion)"
"BRAND_REPO=$src"
"BRAND_DEB_SHA256=$sha"
$cn = if ($key -match 'CN="([^"]+)"') { $matches[1] } elseif ($key -match 'CN=([^,]+)') { $matches[1] } else { $key }   # 'CN="Brave Software, Inc.", ...'
"BRAND_KEY=$cn"

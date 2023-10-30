#!/usr/bin/env pwsh

$ErrorActionPreference = 'Stop'

# Need For Internal Repo
$GithubAccessToken = $GITHUB_TOKEN
if (!$GithubAccessToken) {
    Write-Error "No Github Token"
}

$Headers = @{
    "Authorization" = "Bearer $PersonalAccessToken"
}

$inputRepo = if ($repo) {
  "${repo}"
} else {
  "${r}"
}

$version = if ($version) {
  "${version}"
} else {
  "${v}"
}

$exeName = if ($exe) {
  "${exe}"
} else {
  "${e}"
}

$owner, $repoName = $inputRepo.Split('/')

if ($exeName -eq "") {
  $exeName = "${repoName}"
}

if ([Environment]::Is64BitProcess) {
  $arch = "x86_64"
} else {
  $arch = "i386"
}

$BinDir = "$Home\bin"
$downloadedZip = "$BinDir\${exeName}.zip"
$downloadedExe = "$BinDir\${exeName}.exe"
$Target = "Windows_$arch"
$Release_Name = "${exeName}_${Target}.zip"

# GitHub requires TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$Headers = @{
    Authorization="token ${GithubAccessToken}";
}

$Github_API = "https://api.github.com/repos"
$Github_Repo = "${Github_API}/${owner}/${repoName}"
$Github_Release = if ($version) {
    "$Github_Repo/releases/latest"
} else {
    "$Github_Repo/releases/tags/$version"
}

# Get Github ReleaseID of the asset based on Gitleaks Release Name.
$Github_Release_Asset_Id = ((Invoke-WebRequest $Github_Release -Headers $headers | ConvertFrom-Json)[0].assets | where { $_.name -eq $Release_Name })[0].id

$Download_Url = "https://" + $GithubAccessToken + ":@api.github.com/repos/${owner}/${repoName}/releases/assets/$Github_Release_Asset_Id"

$Headers.Add("Accept", "application/octet-stream")

if (!(Test-Path $BinDir)) {
  New-Item $BinDir -ItemType Directory | Out-Null
}

Invoke-WebRequest -Uri $Download_Url -Headers $Headers -OutFile $downloadedZip -UseBasicParsing -ErrorAction Stop

function Check-Command {
  param($Command)
  $found = $false
  try
  {
      $Command | Out-Null
      $found = $true
  }
  catch [System.Management.Automation.CommandNotFoundException]
  {
      $found = $false
  }

  $found
}

if (Check-Command -Command Expand-Archive) {
  Invoke-Expression "Expand-Archive -Force -Path $downloadedZip -DestinationPath $BinDir"
} else {
  function Expand-Zip($tarFile, $dest) {

      if (-not (Get-Command Expand-7Zip -ErrorAction Ignore)) {
          Install-Package -Scope CurrentUser -Force 7Zip4PowerShell > $null
      }

      Expand-7Zip $tarFile $dest
  }

  Expand-Zip $downloadedZip $BinDir
}

Remove-Item $downloadedZip -Force

$User = [EnvironmentVariableTarget]::User
$Path = [Environment]::GetEnvironmentVariable('Path', $User)
if (!(";$Path;".ToLower() -like "*;$BinDir;*".ToLower())) {
  [Environment]::SetEnvironmentVariable('Path', "$Path;$BinDir", $User)
  $Env:Path += ";$BinDir"
}

Write-Output "Installed in $downloadedExe"
Write-Output "Run '${exeName} version'"
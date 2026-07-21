$solutionRoot = Split-Path -Parent $PSScriptRoot
$localDotNet = Join-Path $solutionRoot '.tools\dotnet'

if (-not (Test-Path -LiteralPath (Join-Path $localDotNet 'dotnet.exe'))) {
    throw 'The local .NET SDK was not found. Install .NET 10 or restore .tools/dotnet first.'
}

$env:PATH = "$localDotNet;$env:PATH"

$workspaceNuGet = Join-Path $solutionRoot '.nuget'
$workspaceTemp = Join-Path $workspaceNuGet 'temp'
New-Item -ItemType Directory -Force -Path $workspaceTemp | Out-Null
$env:NUGET_PACKAGES = Join-Path $workspaceNuGet 'packages'
$env:NUGET_HTTP_CACHE_PATH = Join-Path $workspaceNuGet 'http-cache'
$env:TEMP = $workspaceTemp
$env:TMP = $workspaceTemp

$solutionRoot = Split-Path -Parent $PSScriptRoot
$localDotNet = Join-Path $solutionRoot '.tools\dotnet'

if (-not (Test-Path -LiteralPath (Join-Path $localDotNet 'dotnet.exe'))) {
    throw 'The local .NET SDK was not found. Install .NET 10 or restore .tools/dotnet first.'
}

$env:PATH = "$localDotNet;$env:PATH"

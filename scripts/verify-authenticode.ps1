# Authenticate the final standalone EXE against Windows public trust.
# SignTool verifies every signature and requires an RFC3161 timestamp.
# The expected certificate subject is supplied by protected CI configuration.
# No private certificate or trust-store modification is performed here.
# Publication consumes these verified bytes, followed by fresh SHA256 checksums.
param([Parameter(Mandatory=$true)][string]$Executable,
      [Parameter(Mandatory=$true)][string]$Publisher)
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($Publisher)) { throw 'Expected public publisher is required' }
$signature = Get-AuthenticodeSignature -LiteralPath $Executable
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -cne $Publisher) {
    throw "Untrusted signature or unexpected publisher: $($signature.Status)"
}
if ($null -eq $signature.TimeStamperCertificate) { throw 'Missing public timestamp' }
$sdk = Get-ChildItem 'C:/Program Files (x86)/Windows Kits/10/bin/*/x64/signtool.exe' |
    Sort-Object FullName -Descending | Select-Object -First 1
if ($null -eq $sdk) { throw 'Windows SDK SignTool is unavailable' }
& $sdk.FullName verify /pa /all /v /tw $Executable
if ($LASTEXITCODE -ne 0) { throw 'SignTool trust/timestamp verification failed' }

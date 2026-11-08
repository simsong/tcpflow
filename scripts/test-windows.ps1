# Verify the actual standalone Windows executable using checked-in PCAPs.
# Reconstruction must reproduce hashes for IPv4, VLAN and IPv6 flows.
# Input and output directories contain spaces to exercise command arguments.
# DFXML must parse successfully and the executable must report its version.
# Release jobs rerun this check against the final Authenticode-signed bytes.
# Unsupported BPF filters must produce a failing exit code and useful CLI text.
param([Parameter(Mandatory=$true)][string]$Executable)
$ErrorActionPreference = 'Stop'
$exe = (Resolve-Path -LiteralPath $Executable).Path
$root = Split-Path $PSScriptRoot -Parent
$work = Join-Path ([IO.Path]::GetTempPath()) ('tcpflow runtime ' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $expectedVersion = (Select-String -Path (Join-Path $root 'configure.ac') -Pattern '^AC_INIT\(TCPFLOW, ([^,]+),').Matches[0].Groups[1].Value
    $version = & $exe -V | Out-String
    # The historical CLI returns 1 for -V; verify that contract explicitly.
    if ($LASTEXITCODE -ne 1 -or $version.Trim() -cne "TCPFLOW $expectedVersion") { throw 'Unexpected version output' }
    $cases = @(
        @{fixture='test1.pcap'; hashes=@{
            '074.125.019.101.00080-192.168.001.102.50956'='ae30a88136feb0655492bdb75e078643';
            '074.125.019.104.00080-192.168.001.102.50955'='61051e417d34e1354559e3a8901d19d3';
            '192.168.001.102.50955-074.125.019.104.00080'='14e9c335bf54dc4652999e25d99fecfe';
            '192.168.001.102.50956-074.125.019.101.00080'='78b8073093d107207327103e80fbdf43'}};
        @{fixture='test2.pcap'; hashes=@{
            '010.000.000.001.09999-010.000.000.002.36559--42'='b7d0b9ee8a7c1ea94b6b43b5a3e0da83';
            '010.000.000.002.36559-010.000.000.001.09999--42'='c4b95c552616bda3e21d063e8ee2e332'}};
        @{fixture='test4.pcap'; hashes=@{
            '2001_0_53aa_64c_422_2ece_a29c_9cf6.51391-2001_67c_1220_809__93e5_916.00080'='2600d38f9524c66f190212bbdb6f3c96';
            '2001_67c_1220_809__93e5_916.00080-2001_0_53aa_64c_422_2ece_a29c_9cf6.51391'='2a8f64558ad7a1731e4950a3f7f16913'}}
    )
    foreach ($case in $cases) {
        $inputFile = Join-Path $work $case.fixture
        Copy-Item (Join-Path $root ('tests/' + $case.fixture)) $inputFile
        $output = Join-Path $work ($case.fixture + ' output')
        & $exe -o $output -X (Join-Path $output 'report.xml') -r $inputFile
        if ($LASTEXITCODE -ne 0) { throw "Reconstruction failed: $($case.fixture)" }
        foreach ($entry in $case.hashes.GetEnumerator()) {
            $hash = (Get-FileHash -LiteralPath (Join-Path $output $entry.Key) -Algorithm MD5).Hash
            if ($hash -ine $entry.Value) { throw "Incorrect reconstructed bytes: $($entry.Key)" }
        }
        $null = [xml](Get-Content -Raw -LiteralPath (Join-Path $output 'report.xml'))
    }
    $diagnostic = & $exe -o (Join-Path $work 'unsupported filter') -r (Join-Path $work 'test1.pcap') tcp 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -or $diagnostic -notmatch 'BPF filters are unsupported') {
        throw "Missing unsupported-filter diagnostic: $diagnostic"
    }
} finally { Remove-Item -LiteralPath $work -Recurse -Force }
exit 0

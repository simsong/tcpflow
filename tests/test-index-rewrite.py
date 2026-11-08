#!/usr/bin/env python3
# Exercise the security boundary through the real tcpflow executable.
# Packet fixtures are generated in a disposable directory for reproducibility.
# The executable path is supplied by the Automake shell test wrapper.
# Assertions check observable behavior rather than implementation details.
# No root privileges, external network access or mocked services are used.
import os, struct, subprocess, sys, tempfile
from pathlib import Path
import time

def capture(payload=b'A', seq=100, sport=40000):
    tcp = struct.pack('!HHIIBBHHH', sport, 80, seq, 0, 80, 16, 0, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20+len(tcp), 0, 0, 64, 6, 0, bytes([10,0,0,1]), bytes([10,0,0,2]))
    frame = bytes(12) + b'\x08\x00' + ip + tcp
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame

exe = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    proc = subprocess.Popen([exe, '-I', '-o', 'flows', '-r', '/dev/stdin'], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        proc.stdin.write(capture()); proc.stdin.flush()
        deadline = time.monotonic() + 10
        while not list(Path('flows').glob('*.findx')):
            if proc.poll() is not None or time.monotonic() > deadline:
                raise AssertionError('capture did not create an index')
            time.sleep(.02)
        index = next(Path('flows').glob('*.findx'))
        index.rename('held.findx')
        Path('victim').write_text('preserve me')
        index.symlink_to(Path('victim').resolve())
        proc.stdin.close()
        assert proc.wait(timeout=20) == 0
        assert Path('victim').read_text() == 'preserve me', 'index rewrite followed substituted path'
        assert Path('held.findx').read_text() == '0|1.000000|1\n'
    finally:
        if proc.poll() is None: proc.kill(); proc.wait()

    # A two-descriptor budget evicts the first flow before final cleanup.
    data = capture() + capture(b'B', 110)[24:] + capture(b'C', 105)[24:] + capture(b'D', 100, 40001)[24:]
    Path('eviction.pcap').write_bytes(data)
    subprocess.run([exe, '-I', '-f', '2', '-o', 'evicted', '-r', 'eviction.pcap'], check=True, timeout=20, stderr=subprocess.DEVNULL)
    first = next(Path('evicted').glob('*40000*.findx'))
    assert [int(line.split('|')[0]) for line in first.read_text().splitlines()] == [0, 5, 10]

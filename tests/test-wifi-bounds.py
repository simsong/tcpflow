#!/usr/bin/env python3
# Exercise the security boundary through the real tcpflow executable.
# Packet fixtures are generated in a disposable directory for reproducibility.
# The executable path is supplied by the Automake shell test wrapper.
# Assertions check observable behavior rather than implementation details.
# No root privileges, external network access or mocked services are used.
import os, struct, subprocess, sys, tempfile
from pathlib import Path
import zlib
exe = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    frames = []
    for fc, body in [(0x88, b''), (0x08, bytes.fromhex('aaaa0300000008'))]:
        frame = struct.pack('<H', fc) + bytes(22) + body
        frames.append(frame + struct.pack('<I', zlib.crc32(frame)))
    data = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 105)
    for frame in frames:
        data += struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame
    Path('short.pcap').write_bytes(data)
    subprocess.run([exe, '-o', 'flows', '-r', 'short.pcap'], check=True, timeout=20)
    assert not list(Path('flows').glob('010.*')), 'malformed frames created a flow'

#!/usr/bin/env python3
# Exercise the security boundary through the real tcpflow executable.
# Packet fixtures are generated in a disposable directory for reproducibility.
# The executable path is supplied by the Automake shell test wrapper.
# Assertions check observable behavior rather than implementation details.
# No root privileges, external network access or mocked services are used.
import os, struct, subprocess, sys, tempfile
from pathlib import Path
import gzip, bz2, lzma, zipfile, shutil

def capture(payload=b'A'):
    tcp = struct.pack('!HHIIBBHHH', 40000, 80, 100, 0, 80, 16, 0, 0, 0) + payload
    ip = struct.pack('!BBHHHBBH4s4s', 69, 0, 20+len(tcp), 0, 0, 64, 6, 0, bytes([10,0,0,1]), bytes([10,0,0,2]))
    frame = bytes(12) + b'\x08\x00' + ip + tcp
    return struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1) + struct.pack('<IIII', 1, 0, len(frame), len(frame)) + frame

exe = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory() as tmp:
    os.chdir(tmp)
    raw = capture()
    tested = 0
    for suffix, compress in [('gz', gzip.compress), ('bz2', bz2.compress), ('xz', lzma.compress), ('lzma', lambda b: lzma.compress(b, format=lzma.FORMAT_ALONE)), ('zip', None)]:
        program = {'gz': 'gunzip', 'bz2': 'bunzip2', 'xz': 'unxz', 'lzma': 'unlzma', 'zip': 'unzip'}[suffix]
        if not shutil.which(program):
            print('SKIP unavailable decompressor:', program)
            continue
        tested += 1
        for prefix in ["capture'; touch INJECTED; #", '-capture with spaces']:
            name = prefix + '.' + suffix
            if compress:
                Path(name).write_bytes(compress(raw))
            else:
                with zipfile.ZipFile(name, 'w') as z: z.writestr('capture.pcap', raw)
            subprocess.run([exe, '-o', 'flows-'+suffix, '-r', name], check=True, timeout=20, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            assert not Path('INJECTED').exists(), 'filename executed shell syntax'
            flows = list(Path('flows-'+suffix).glob('010.*'))
            assert flows and all(p.read_bytes() == b'A' for p in flows), 'decompression changed payload'

    if not tested: sys.exit(77)

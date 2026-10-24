"""Exercise real logrotate against private fixture logs without installing cron."""
import gzip
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import configure


@unittest.skipUnless(os.name == 'posix' and os.geteuid() == 0 and shutil.which('logrotate'),
                     'requires Linux root and logrotate')
class LiveRotationTests(unittest.TestCase):
    def test_size_rotation_compresses_and_keeps_existing_writer_usable(self):
        with tempfile.TemporaryDirectory(prefix='nginx-rotation-', dir='/root') as directory:
            root = Path(directory)
            logs = root / 'log/nginx'
            logs.mkdir(parents=True)
            path = logs / 'error.log'
            chunk = b'request rejected\n' * 65536
            with path.open('wb') as writer:
                for _ in range(52):
                    writer.write(chunk)
            original_size = path.stat().st_size
            real_run, real_which = subprocess.run, shutil.which

            def run(args, **kwargs):
                if args == ['crontab', '-l']:
                    return subprocess.CompletedProcess(args, 0, '', '')
                if args == ['crontab', '-']:
                    return subprocess.CompletedProcess(args, 0, '', '')
                return real_run(args, **kwargs)

            with patch.object(configure.shutil, 'which', side_effect=lambda name: '/usr/bin/crontab' if name == 'crontab' else real_which(name)), \
                 patch.object(configure.subprocess, 'run', side_effect=run):
                configure.rotation(root, {})
            with path.open('ab', buffering=0) as writer:
                inode = path.stat().st_ino
                real_run([real_which('logrotate'), '--state', str(root / 'state'),
                          str(root / 'config/waf/logrotate.conf')], check=True, capture_output=True, timeout=25)
                self.assertEqual(path.stat().st_ino, inode)
                self.assertEqual(path.stat().st_size, 0)
                writer.write(b'next event\n')
            self.assertEqual(path.read_bytes(), b'next event\n')
            with gzip.open(logs / 'error.log.1.gz', 'rb') as archive:
                self.assertEqual(sum(len(block) for block in iter(lambda: archive.read(1024 * 1024), b'')), original_size)
            self.assertFalse((logs / 'error.log.1').exists())


if __name__ == '__main__':
    unittest.main()

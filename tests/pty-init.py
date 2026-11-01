"""Exercise the real CLI with a controlling terminal; no passphrase is printed."""
import errno
import json
import os
import pty
import select
import signal
import sys
import time

project, directory = sys.argv[1:]
passphrase = "synthetic acceptance passphrase 2026"
pid, fd = pty.fork()
if pid == 0:
    os.chdir(project)
    os.execvp("node", ["node", "dist/src/cli.js", "init", "--data-dir", directory])

output = b""
stage = 0
status = None
deadline = time.monotonic() + 20
try:
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.1)
        if ready:
            try:
                chunk = os.read(fd, 4096)
            except OSError as error:
                if error.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            output += chunk
            if stage == 0 and b"New passphrase" in output:
                os.write(fd, (passphrase + "\r").encode())
                stage = 1
            if stage == 1 and b"Confirm passphrase" in output:
                os.write(fd, (passphrase + "\r").encode())
                stage = 2
        child, child_status = os.waitpid(pid, os.WNOHANG)
        if child:
            status = child_status
            break
    else:
        os.kill(pid, signal.SIGKILL)
        raise RuntimeError("PTY init timed out")
    if status is None:
        _, status = os.waitpid(pid, 0)
    assert os.waitstatus_to_exitcode(status) == 0, "CLI init failed"
    assert stage == 2, "CLI did not prompt twice"
    assert passphrase.encode() not in output, "Passphrase echoed"
    assert b"Vault initialized" in output, "Missing init success"
    print(json.dumps({"pty": "passed", "echo": False, "exitCode": 0}))
finally:
    os.close(fd)

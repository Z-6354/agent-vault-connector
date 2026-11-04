"""Build with the installed MSVC environment; no Node/Tauri CLI required."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(__file__).resolve().parent
vswhere = Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
installation = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
if not installation:
    raise SystemExit("MSVC Build Tools not found")
vcvars = Path(installation) / "VC/Auxiliary/Build/vcvars64.bat"
raw_env = subprocess.check_output(f'cmd.exe /d /s /c ""{vcvars}" >nul && set"', text=True)
env = os.environ.copy()
for line in raw_env.splitlines():
    if "=" in line and not line.startswith("="):
        key, value = line.split("=", 1)
        env[key] = value
mode = sys.argv[1] if len(sys.argv) > 1 else "test"
command = {"test": ["cargo", "test", "--locked"], "release": ["cargo", "build", "--release", "--locked"], "fetch": ["cargo", "fetch"], "check": ["cargo", "check", "--locked"]}[mode]
start = time.monotonic()
result = subprocess.run(command, cwd=root, env=env)
report = {"command": command, "exit_code": result.returncode, "duration_seconds": round(time.monotonic() - start, 2)}
if mode == "release" and result.returncode == 0:
    exe = root / "target/release/agent-vault-desktop.exe"
    report.update(executable=str(exe), bytes=exe.stat().st_size, sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
print(json.dumps(report), flush=True)
if mode in ("test", "release"):
    (root / "target").mkdir(exist_ok=True)
    (root / "target" / f"{mode}-report.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
raise SystemExit(result.returncode)

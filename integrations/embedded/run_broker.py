"""Start the headless inline broker at the shared per-user discovery path.
No browser, Tauri window, clipboard or credential prompt is opened.
"""
import os
from pathlib import Path
import runpy
import sys
import tempfile

if __name__=='__main__':
    discovery=Path(os.environ.get('EMBEDDED_VAULT_DISCOVERY') or str(Path(tempfile.gettempdir())/'agent-vault-embedded.json'))
    sys.argv=[str(Path(__file__).with_name('broker.py')),'--serve','--discovery-file',str(discovery)]
    runpy.run_path(sys.argv[0],run_name='__main__')

# Root conftest, for all tests.
import os
from pathlib import Path

# requests uses its own CA bundle: trust the dev CA of *.example.test (Vault's
# PKI, exported by scripts/stack_init.py) unless the environment says otherwise
os.environ.setdefault("REQUESTS_CA_BUNDLE", str(Path(__file__).parent / ".dev" / "ca.pem"))

# Root conftest: registers the traffic recorder (tests/traffic) for all tests.
# pytest only accepts `pytest_plugins` here, in the rootdir.
import os
from pathlib import Path

pytest_plugins = ["tests.traffic.recorder"]

# requests uses its own CA bundle: trust the dev CA of *.example.test (Vault's
# PKI, exported by scripts/stack_init.py) unless the environment says otherwise
os.environ.setdefault("REQUESTS_CA_BUNDLE", str(Path(__file__).parent / ".dev" / "ca.pem"))

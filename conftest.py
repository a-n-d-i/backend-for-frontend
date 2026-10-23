# Root conftest: registers the traffic recorder (tests/traffic) for all tests.
# pytest only accepts `pytest_plugins` here, in the rootdir.
import os
from pathlib import Path

pytest_plugins = ["tests.traffic.recorder"]

# requests uses its own CA bundle: trust the dev CA of *.example.test
# (scripts/dev_pki.py) unless the environment says otherwise
os.environ.setdefault("REQUESTS_CA_BUNDLE", str(Path(__file__).parent / "conf" / "pki" / "ca.pem"))

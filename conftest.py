# Root conftest: registers the traffic recorder (tests/traffic) for all tests.
# pytest only accepts `pytest_plugins` here, in the rootdir.
pytest_plugins = ["tests.traffic.recorder"]

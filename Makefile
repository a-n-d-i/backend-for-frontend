.PHONY: test test-unit test-integration test-e2e lint reload logs

test:
	pytest

test-unit:
	pytest tests/unit

test-integration:
	pytest tests/integration

test-e2e:
	pytest tests/e2e

lint:
	ruff check services scripts tests

# Pick up plugin code (lua/) and config.yaml changes (apisix.yaml is hot
# reloaded): APISIX regenerates nginx.conf, new workers load the new code.
reload:
	apisix reload

logs:
	tail -f /usr/local/apisix/logs/error.log

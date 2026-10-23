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
	ruff check plugins tests

# Pick up plugin code and config.yaml changes (apisix.yaml is hot reloaded):
# APISIX re-reads its config, and respawns the runner after it exits.
reload:
	apisix reload
	pkill -f '[b]in/py-runner start' || true
	@# respawn happens 3s after exit
	@sleep 4

logs:
	tail -f /usr/local/apisix/logs/error.log

.PHONY: test test-unit test-integration test-e2e lint coverage coverage-e2e loc reload logs

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
	luacheck lua tests/lua

# Line coverage of the plugin's Lua modules from the Lua unit tests
# (tests/lua; test_sessions needs the stack's Redis). Report: luacov.report.out
coverage:
	rm -f luacov.stats.out luacov.report.out
	LUACOV=1 pytest tests/unit/test_lua.py
	luacov
	sed -n '/^Summary/,$$p' luacov.report.out

# Line coverage of the plugin in the running gateway during the Playwright
# tests (lua/luacov_gateway.lua): reload with coverage on, run the tests,
# reload with it off and wait for the old workers to exit and write their
# counts, merge them. Same report file as `coverage`.
coverage-e2e:
	rm -rf .luacov-gateway luacov.stats.out luacov.report.out
	mkdir .luacov-gateway && touch .luacov-gateway/on
	apisix reload && sleep 2
	pytest tests/e2e; rc=$$?; \
	rm .luacov-gateway/on; apisix reload; sleep 2; \
	for _ in $$(seq 60); do pgrep -f 'worker process is shutting down' >/dev/null || break; sleep 1; done; \
	lua scripts/luacov_merge.lua luacov.stats.out .luacov-gateway/[0-9]*; \
	luacov && sed -n '/^Summary/,$$p' luacov.report.out; \
	exit $$rc

# Lines of code by language: tracked files only, without the vendored Vue
# build and JSON (the generated Keycloak realm export)
loc:
	cloc --vcs=git --exclude-dir=vendor --exclude-ext=json

# Pick up plugin code (lua/) and config.yaml changes (apisix.yaml is hot
# reloaded): APISIX regenerates nginx.conf, new workers load the new code.
reload:
	apisix reload

logs:
	tail -f /usr/local/apisix/logs/error.log

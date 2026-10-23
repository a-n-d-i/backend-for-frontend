ARG APISIX_VERSION=3.19.0
FROM apache/apisix:${APISIX_VERSION}-debian

# The python plugin runner has had no release since 0.2.0 (2022); pin the commit
# so the build stays reproducible.
ARG RUNNER_REF=250b936f489fc540c465b434d427834448104ac4
# Match the container user to the host user so files written into the
# workspace keep the right owner.
ARG USER_UID=1000
ARG USER_GID=1000

USER root

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv git make sudo curl ca-certificates procps less libnss3-tools \
    && rm -rf /var/lib/apt/lists/*

# Re-map the image's apisix user (uid 636) to the host uid and give it a real
# shell + home so VS Code can attach as it.
RUN groupmod -o -g "${USER_GID}" apisix \
    && usermod -o -u "${USER_UID}" -g "${USER_GID}" -s /bin/bash -d /home/apisix apisix \
    # the image has no home dir for apisix, so `usermod -m` would not create one
    && install -d -o apisix -g apisix /home/apisix \
    && chown -R apisix:apisix /usr/local/apisix \
    && echo "apisix ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/apisix \
    # /etc/profile resets PATH in login shells, drop the venv and claude
    && echo 'export PATH="/home/apisix/.local/bin:/opt/venv/bin:$PATH"' > /etc/profile.d/devcontainer.sh

# Python plugin runner. Its requirements.txt pins PyYAML 5.4.1, which does not
# build on Python 3.11, so the dependencies are installed with relaxed pins.
ENV RUNNER_HOME=/opt/apisix-python-plugin-runner \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH
RUN git clone https://github.com/apache/apisix-python-plugin-runner.git "${RUNNER_HOME}" \
    && git -C "${RUNNER_HOME}" checkout "${RUNNER_REF}" \
    # upstream bug: APISIX hands out request id 0 (first request on worker 0),
    # which the runner treats as "no response" and drops the plugin's changes
    && sed -i 's/if not action or id == 0:/if not action:/' "${RUNNER_HOME}/apisix/runner/utils/common.py" \
    && grep -q 'if not action:' "${RUNNER_HOME}/apisix/runner/utils/common.py" \
    && python3 -m venv "${VIRTUAL_ENV}" \
    && pip install --no-cache-dir "a6pluginprotos==0.2.1" "minicache==0.0.1" click PyYAML \
    # make `apisix.runner` / `apisix.plugins` importable without PYTHONPATH,
    # nginx strips the environment of the processes it spawns
    && echo "${RUNNER_HOME}" > "$(python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')/apisix-runner.pth" \
    # the runner only loads plugins from its own apisix/plugins package:
    # point that package at the workspace
    && rm -rf "${RUNNER_HOME}/apisix/plugins" \
    && ln -s /workspace/plugins "${RUNNER_HOME}/apisix/plugins"

# Plugin runtime dependencies (requirements.txt, pulled in by -dev) and test
# tools. Playwright's Chromium (+ its system libraries) is for the SPA browser
# tests; it goes to a shared path so the apisix user finds it.
ENV PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
COPY requirements.txt requirements-dev.txt /tmp/
RUN pip install --no-cache-dir -r /tmp/requirements-dev.txt \
    && playwright install --with-deps chromium \
    && chown -R apisix:apisix "${VIRTUAL_ENV}" "${PLAYWRIGHT_BROWSERS_PATH}"

# Secrets and the PKI live in Vault, nothing is baked into the image:
# gateway-entrypoint.sh hands APISIX its Vault token and trusts the CA of
# Vault's PKI at start (both from .dev/, written by the vault-init job).
# requests uses its own CA bundle unless pointed at the system one.
ENV REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
COPY --chmod=755 .devcontainer/gateway-entrypoint.sh /usr/local/bin/gateway-entrypoint.sh

# APISIX reads its config straight from the workspace; apisix.yaml (routes) is
# hot reloaded, config.yaml needs a container restart.
RUN ln -sf /workspace/conf/config.yaml /usr/local/apisix/conf/config.yaml \
    && ln -sf /workspace/conf/apisix.yaml /usr/local/apisix/conf/apisix.yaml \
    # log to files instead of the container stdout/stderr so `make logs` works
    && rm /usr/local/apisix/logs/access.log /usr/local/apisix/logs/error.log

USER apisix

# Claude Code (native installer, no node needed). Its config incl. login lives
# in CLAUDE_CONFIG_DIR, which is a volume so it survives rebuilds.
ENV PATH=/home/apisix/.local/bin:$PATH \
    CLAUDE_CONFIG_DIR=/home/apisix/.claude
RUN mkdir -p "${CLAUDE_CONFIG_DIR}" \
    && curl -fsSL https://claude.ai/install.sh | bash \
    && claude --version

ENTRYPOINT ["/usr/local/bin/gateway-entrypoint.sh"]
CMD ["docker-start"]

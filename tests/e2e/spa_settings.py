import os

# origin of the SPA and of the BFF's redirect URI (see conf/apisix.yaml)
APP_URL = os.environ.get("APP_URL", "https://app.example.test")
ISSUER = os.environ.get("ISSUER", "https://auth.example.test/realms/demo")
# the demo user in conf/keycloak/demo-realm.json
USERNAME, PASSWORD, EMAIL = "alice", "alice-password", "alice@example.test"

import os

# origin of the SPA and of the BFF's redirect URI (see conf/apisix.yaml)
APP_URL = os.environ.get("APP_URL", "http://localhost:9080")

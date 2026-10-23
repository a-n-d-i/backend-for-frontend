# Vault server for the dev stack: persistent (file storage in the vault-data
# volume), initialized and unsealed by the vault-init job
# (scripts/stack_init.py), which keeps unseal key and root token in .dev/.
#
# Plain http: Vault is reached only inside the Docker network (and through
# the gateway as https://vault.example.test). Production: TLS listener,
# auto-unseal with a KMS/HSM, no root token at rest.

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr      = "http://vault:8200"
disable_mlock = true
ui            = true

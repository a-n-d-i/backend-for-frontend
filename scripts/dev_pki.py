"""
Development PKI for *.example.test (RFC 6761 reserved, never on the internet).

Creates, if missing or about to expire (or always with --force):
  conf/pki/ca.pem          CA certificate: import into your browser / OS once
  conf/pki/server.pem      server certificate for example.test, *.example.test
  conf/pki/server-key.pem  its private key

Runs automatically as the `pki` service before the compose stack starts. The
gateway reads certificate and key from here at start
(.devcontainer/gateway-entrypoint.sh); conf/apisix.yaml only references them.

conf/pki/ is per machine and gitignored. Never commit or publish it.
A CA you trust in your browser vouches for every certificate signed with its
key; if those keys were public (say, on GitHub), anyone could impersonate the
sites it covers to you. This script limits the damage on two levels: the CA
is name-constrained to example.test, and its private key is never written
anywhere, so no further certificate can be issued with it once this script
exits. The server key in server-key.pem still lets its holder impersonate
*.example.test to everyone who trusts the CA: keep it on your machine.
Remove the CA from your trust store when you no longer need it.

    python scripts/dev_pki.py            # create if missing or expiring
    python scripts/dev_pki.py --force    # rotate (then re-import ca.pem)
"""
import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
PKI = ROOT / "conf" / "pki"
DOMAIN = "example.test"
# renew this long before the server certificate expires
RENEW_BEFORE = datetime.timedelta(days=30)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "tokenhandler dev"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _current_expiry():
    """Expiry of the existing server certificate, or None if the PKI is incomplete."""
    if not all((PKI / f).exists() for f in ("ca.pem", "server.pem", "server-key.pem")):
        return None
    return x509.load_pem_x509_certificate((PKI / "server.pem").read_bytes()).not_valid_after_utc


def generate():
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = _name(f"{DOMAIN} dev CA (key discarded)")
    ca = (x509.CertificateBuilder()
          .subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number())
          .not_valid_before(now - datetime.timedelta(minutes=5))
          .not_valid_after(now + datetime.timedelta(days=800))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                       data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                       crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
          # only example.test and its subdomains, nothing else
          .add_extension(x509.NameConstraints(permitted_subtrees=[x509.DNSName(DOMAIN)], excluded_subtrees=None),
                         critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(_name(f"*.{DOMAIN}")).issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            # browsers cap TLS server certificates at 398 days
            .not_valid_after(now + datetime.timedelta(days=397))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(DOMAIN), x509.DNSName(f"*.{DOMAIN}")]),
                           critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    del ca_key  # never written: no more certificates can be issued

    PKI.mkdir(parents=True, exist_ok=True)
    (PKI / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (PKI / "server.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file = PKI / "server-key.pem"
    key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    key_file.chmod(0o600)
    return cert.not_valid_after_utc


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--force", action="store_true", help="rotate even if the PKI is present and valid")
    args = parser.parse_args()

    expiry = _current_expiry()
    if not args.force and expiry and expiry - RENEW_BEFORE > datetime.datetime.now(datetime.timezone.utc):
        print(f"{PKI}: present, server certificate valid until {expiry:%Y-%m-%d}")
        return
    expiry = generate()
    print(f"wrote {PKI}/ca.pem, server.pem, server-key.pem (valid until {expiry:%Y-%m-%d}).\n"
          f"Import ca.pem into your browser / OS as a trusted authority (again, if you rotated), "
          f"and never commit or publish {PKI}.")


if __name__ == "__main__":
    main()

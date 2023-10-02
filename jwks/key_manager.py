from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta
import base64

def generate_rsa_key():

    # generate an RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # serialize the private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # generate the corresponding public key
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem, public_pem

def generate_key_id():

    # generate a unique Key ID (kid) using a combination of current timestamp and a random value
    now = datetime.now()
    timestamp = now.strftime("%Y%m%d%H%M%S")
    random_bytes = base64.urlsafe_b64encode(os.urandom(8)).decode('utf-8')
    kid = f"{timestamp}-{random_bytes}"
    return kid

def generate_key_pair():

    # generate an RSA key pair
    private_key, public_key = generate_rsa_key()

    # generate a unique Key ID (kid)
    kid = generate_key_id()

    # set the expiration timestamp (e.g., 1 year from now)
    expiry_timestamp = datetime.now() + timedelta(days=30)

    return kid, private_key, public_key, expiry_timestamp

from django.db import models
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta
from .key_manager import generate_key_pair # import the key generation function

class JWK(models.Model):

    # model to represent a JSON Web Key (JWK).

    kid = models.CharField(max_length=255, unique=True)
    public_key = models.TextField()
    expiry_timestamp = models.DateTimeField()

    def __str__(self):
        return self.kid

    class Meta:
        verbose_name = 'JSON Web Key'
        verbose_name_plural = 'JSON Web Keys'

    @classmethod
    def generate_and_save_key(cls):

        # generate a new key pair, save it to the database, and return the new JWK instance.

        kid, private_key, public_key, expiry_timestamp = generate_key_pair()

        # serialize the public key to store it in the database
        public_pem = public_key.decode('utf-8')

        jwk = cls(kid=kid, public_key=public_pem, expiry_timestamp=expiry_timestamp)
        jwk.save()

        return jwk

from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rest_framework import status
from .models import JWKS
from jwks.key_manager import KeyManager
from .key_manager import generate_key_pair
from .key_manager import generate_rsa_key
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

class JWKSModelTestCase(TestCase):
    def setUp(self):
        JWKS.objects.create(kid='key1', public_key='public_key1', expiry_timestamp=1600000000)
        JWKS.objects.create(kid='key2', public_key='public_key2', expiry_timestamp=1700000000)

    def test_jwks_model(self):
        key1 = JWKS.objects.get(kid='key1')
        key2 = JWKS.objects.get(kid='key2')
        self.assertEqual(key1.public_key, 'public_key1')
        self.assertEqual(key2.public_key, 'public_key2')

class JWKSAPITestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client = APIClient()
        self.jwks_url = reverse('jwks')
        self.auth_url = reverse('auth_view')

    def test_get_jwks(self):
        response = self.client.get(self.jwks_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # add assertions to check the JWKS response data

    def test_authenticate_user(self):
        response = self.client.post(self.auth_url, {'username': 'testuser', 'password': 'testpassword'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # add asertions to check the JWT response data

    def test_authenticate_user_with_expired_key(self):
        # create an expired key in the JWKS database
        JWKS.objects.create(kid='expired_key', public_key='public_key_expired', expiry_timestamp=1500000000)

        response = self.client.post(self.auth_url, {'username': 'testuser', 'password': 'testpassword', 'expired': 'true'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # adds assertions to check the JWT response data signed with the expired key

    def test_authenticate_invalid_user(self):
        response = self.client.post(self.auth_url, {'username': 'invaliduser', 'password': 'invalidpassword'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_create_jwks_entry(self):
        key_pair = KeyManager().generate_key_pair()
        kid = 'new_key'
        response = self.client.post(self.jwks_url, {'kid': kid, 'public_key': key_pair['public_key'], 'expiry_timestamp': 1700000000})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        # ensure a new JWKS entry is created

    def test_get_jwks_with_expired_keys(self):
        # create and add an expired key to the JWKS database
        JWKS.objects.create(kid='expired_key', public_key='public_key_expired', expiry_timestamp=1500000000)
        response = self.client.get(self.jwks_url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # ensure that expired keys are not included in the response

    def test_delete_jwks_entry(self):
        # create and add a JWKS entry
        key_pair = KeyManager().generate_key_pair()
        kid = 'new_key'
        JWKS.objects.create(kid=kid, public_key=key_pair['public_key'], expiry_timestamp=1700000000)
        response = self.client.delete(reverse('jwks-detail', args=[kid]))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        # ensure the JWKS entry is deleted

class KeyManagerTestCase(TestCase):
    def test_generate_key_pair(self):
        kid, private_key, public_key, expiry_timestamp = generate_key_pair()

        # assertions to verify that key_pair is generated correctly
        self.assertIsNotNone(kid)
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(expiry_timestamp)

    def test_generate_key_id(self):
        # test generate_key_id function
        kid = generate_key_id()

        # assertion to verify that kid is generated correctly
        self.assertIsNotNone(kid)

    def test_generate_rsa_key(self):
        private_key, public_key = generate_rsa_key()

        # assertions to verify that private_key and public_key are generated correctly
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)

        # check the key size (e.g., 2048 bits)
        private_key_object = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        self.assertEqual(private_key_object.key_size, 2048)

        public_key_object = serialization.load_pem_public_key(public_key, backend=default_backend())
        self.assertEqual(public_key_object.key_size, 2048)

        # check key encoding (PEM format)
        self.assertTrue(private_key.startswith(b'-----BEGIN RSA PRIVATE KEY-----'))
        self.assertTrue(public_key.startswith(b'-----BEGIN PUBLIC KEY-----'))

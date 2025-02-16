import pytest
import requests
import datetime
import time
import jwt
import json
from jwt.exceptions import ExpiredSignatureError
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Base URL of the running Flask server
BASE_URL = "http://localhost:8080"

# Fixture to generate a test RSA key pair (public and private)
@pytest.fixture(scope='module')
def generate_test_rsa_keys():
    """Generates a test RSA key pair for use in the tests."""
    # Generate a new private RSA key with a public exponent of 65537 and key size of 2048 bits
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    # Extract the public key corresponding to the private key
    public_key = private_key.public_key()
    # Return both private and public keys for use in other tests
    return private_key, public_key


# Test that checks if the JWKS endpoint returns valid keys
def test_jwks_contains_valid_keys():
    """Tests if the JWKS endpoint returns valid public keys."""
    # Send a GET request to fetch the JWKS 
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    # Assert that the response status is 200 
    assert response.status_code == 200
    jwks = response.json()
    
    # Assert that the response contains a 'keys' field and that it has at least one key
    assert 'keys' in jwks
    assert len(jwks['keys']) > 0

    # For each key in the 'keys' array, assert that it contains required fields
    for key in jwks['keys']:
        assert 'kid' in key  # Ensure key ID exists
        assert 'kty' in key and key['kty'] == 'RSA'  # Ensure the key type is RSA
        assert 'n' in key and 'e' in key  # Ensure 'n' (modulus) and 'e' (exponent) are present


# Test that checks if the server can generate a valid JWT token
def test_generate_jwt():
    """Tests if the server can generate a valid JWT token."""
    # Prepare data for the authentication request (e.g., username)
    data = {'username': 'testuser'}
    # Send a POST request to the /auth endpoint to generate the JWT
    response = requests.post(f"{BASE_URL}/auth", json=data)
    # Assert that the response status is 200 
    assert response.status_code == 200
    # Extract the token from the response
    token = response.json().get('token')
    assert token is not None  # Ensure a token is returned
    
    # Extract the JWT header without verifying its signature
    header = jwt.get_unverified_header(token)
    # Assert that the JWT header contains a key ID (kid)
    assert 'kid' in header


# Test that checks if an expired token raises an exception when decoded
def test_expired_token():
    """Tests if requesting an expired token actually returns an expired token."""
    data = {'username': 'testuser'}
    # Request an expired token by setting the 'expired' query parameter to true
    response = requests.post(f"{BASE_URL}/auth?expired=true", json=data)
    assert response.status_code == 200
    token = response.json().get('token')
    assert token is not None  # Ensure a token is returned

    # Fetch the JWKS from the server to obtain the public keys
    jwks_response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    jwks = jwks_response.json()
    
    # Extract the 'kid' from the JWT header to find the corresponding public key
    header = jwt.get_unverified_header(token)
    kid = header['kid']
    public_key_pem = None
    
    # Iterate over the keys in the JWKS to find the public key matching the 'kid'
    for key in jwks['keys']:
        if key['kid'] == kid:
            public_key_pem = key
            break

    # If no matching public key was found, raise an exception
    if public_key_pem is None:
        raise ValueError("Public key not found")

    # Convert the public key from the JWK format to an RSA public key object
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(public_key_pem))

    # Decode the token using the public key and check if it raises an 'ExpiredSignatureError'
    with pytest.raises(ExpiredSignatureError):
        decoded_token = jwt.decode(token, public_key, algorithms=['RS256'])


# Test that checks if the server correctly handles invalid authentication requests
def test_invalid_auth_request():
    """Tests if sending an invalid request to /auth is handled properly."""
    # Send an invalid POST request to the /auth endpoint (missing 'username' in the request body)
    response = requests.post(f"{BASE_URL}/auth", json={})
    # Assert that the server responds with a 400 or 500 error status code
    assert response.status_code == 400 or response.status_code == 500


# Test that checks if expired keys are properly removed from the JWKS endpoint
def test_expired_jwks_key_removal():
    """Tests if expired keys are removed from the JWKS endpoint."""
    time.sleep(60)  # Wait for a potential key expiration (e.g., 60 seconds)
    # Send a GET request to fetch the JWKS from the server
    response = requests.get(f"{BASE_URL}/.well-known/jwks.json")
    assert response.status_code == 200  # Ensure the request is successful
    jwks = response.json()
    
    # Assert that all keys in the JWKS have not expired (check 'exp' field)
    assert all(datetime.datetime.utcnow() < datetime.datetime.strptime(k['exp'], "%Y-%m-%dT%H:%M:%SZ") for k in jwks['keys'])


# Entry point for running the tests using pytest if the script is executed directly
if __name__ == "__main__":
    pytest.main()

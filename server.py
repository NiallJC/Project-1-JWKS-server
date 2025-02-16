import datetime
import uuid
import json
import base64
from datetime import datetime, timezone, timedelta
from flask import Flask, request, jsonify, make_response
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# Dictionary to store generated keys (not persistent; resets on server restart)
stored_keys = {}

# Function to generate and store a new RSA key pair with an expiration time
def generate_rsa_key_pair(key_id, expiration_minutes=30):
    private_rsa_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    private_key_pem = private_rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = private_rsa_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    stored_keys[key_id] = {
        'private_key': private_key_pem,
        'public_key': public_key_pem,
        'expiration_time': datetime.now(timezone.utc) + timedelta(minutes=expiration_minutes),
    }

    return private_key_pem, public_key_pem

# Ensure there is at least one valid key and one expired key
def ensure_valid_and_expired_keys_exist():
    if not stored_keys:
        generate_rsa_key_pair(str(uuid.uuid4()))  
        generate_rsa_key_pair(str(uuid.uuid4()), expiration_minutes=-10)  

# Route to authenticate a user and issue a JWT token
@app.route('/auth', methods=['POST'])
def authenticate_user():
    request_data = request.get_json()
    include_expired_token = request.args.get('expired', 'false').lower() == 'true'

    ensure_valid_and_expired_keys_exist()
    
    if include_expired_token:
        key_id = next((key for key, key_data in stored_keys.items() if key_data['expiration_time'] < datetime.now(timezone.utc)), None)
        if not key_id:
            return make_response(jsonify({'message': 'No expired keys available'}), 400)
    else:
        key_id = next((key for key, key_data in stored_keys.items() if key_data['expiration_time'] > datetime.now(timezone.utc)), None)
        if not key_id:
            return make_response(jsonify({'message': 'No valid keys available'}), 500)

    private_key = serialization.load_pem_private_key(
        stored_keys[key_id]['private_key'], password=None, backend=default_backend()
    )

    token_payload = {
        'sub': request_data['username'],
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(minutes=30 if not include_expired_token else -30),
    }

    token = jwt.encode(token_payload, private_key, algorithm='RS256', headers={'kid': key_id})

    return jsonify({'token': token})

# Route to return the public keys in JWKS format
@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    public_keys = []

    for key_id, key_data in stored_keys.items():
        if key_data['expiration_time'] > datetime.now(timezone.utc):
            public_key = serialization.load_pem_public_key(
                key_data['public_key'], backend=default_backend()
            )
            public_key_numbers = public_key.public_numbers()

            n_base64_url = base64.urlsafe_b64encode(
                public_key_numbers.n.to_bytes((public_key_numbers.n.bit_length() + 7) // 8, 'big')
            ).decode('utf-8').rstrip("=")
            e_base64_url = base64.urlsafe_b64encode(
                public_key_numbers.e.to_bytes((public_key_numbers.e.bit_length() + 7) // 8, 'big')
            ).decode('utf-8').rstrip("=")

            jwk = {
                'kid': key_id,
                'kty': 'RSA',
                'alg': 'RS256',
                'use': 'sig',
                'n': n_base64_url,
                'e': e_base64_url,
                'exp': key_data['expiration_time'].strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            public_keys.append(jwk)

    return jsonify({'keys': public_keys})

if __name__ == '__main__':
    ensure_valid_and_expired_keys_exist()
    app.run(port=8080, debug=True)

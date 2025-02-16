import datetime 
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Dictionary to store generated keys, indexed by key ID (kid)
KEY_STORAGE = {}

# Function to generate a pair of RSA keys (private and public)
def generate_rsa_key_pair(key_id, key_expiry_minutes=30):
    # Generate a new private RSA key with specified public exponent and key size
    private_rsa_key = rsa.generate_private_key(
        public_exponent=65537,  # Common public exponent used in RSA
        key_size=2048,  # Key size in bits (2048 bits for security)
        backend=default_backend()  # Use the default backend for cryptographic operations
    )

    # Extract the public key from the generated private key
    public_rsa_key = private_rsa_key.public_key()

    # Convert the private key to PEM format (no encryption applied)
    private_key_pem = private_rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,  # Encode as PEM format (base64-encoded)
        format=serialization.PrivateFormat.TraditionalOpenSSL,  # Standard format for private keys
        encryption_algorithm=serialization.NoEncryption()  # No encryption on the private key
    )

    # Convert the public key to PEM format
    public_key_pem = public_rsa_key.public_bytes(
        encoding=serialization.Encoding.PEM,  # PEM format for public key
        format=serialization.PublicFormat.SubjectPublicKeyInfo  # Standard format for public keys
    )

    # Calculate the key expiry time based on the provided expiry duration (default 30 minutes)
    key_expiry_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=key_expiry_minutes)
    
    # Store the private key, public key, and expiry time in the key storage dictionary
    KEY_STORAGE[key_id] = {
        'private_key_pem': private_key_pem,
        'public_key_pem': public_key_pem,
        'expiry_time': key_expiry_time,
    }

    # Return both the private and public key in PEM format
    return private_key_pem, public_key_pem

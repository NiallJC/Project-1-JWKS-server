# Implementing a basic JWKS Server
![Python Version](https://img.shields.io/badge/python-blue) 

---

## **Overview**
This project implements a simple JSON Web Key Set (JWKS) server that provides public keys for verifying JSON Web Tokens (JWTs). The server supports key expiration, authentication, and issuance of JWTs, including handling expired keys.
This project is built for educational purposes, demonstrating key management in a secure authentication system.

---

## 📌 Requirements

- ✅ Generates RSA key pairs with unique key IDs (kid) and expiry timestamps.
- ✅ Implements a RESTful API running on port 8080.
- ✅ Provides a JWKS endpoint (/jwks) to serve public keys (only non-expired keys).
- ✅ Implements an authentication endpoint (/auth) that issues JWTs.
- ✅ Supports an "expired" query parameter, issuing JWTs signed with expired keys when requested.
- ✅ Includes unit tests and black-box testing with >80% coverage.

---

## **📌 End Points**

| **Method** | **Endpoint** | **Description** | 
|--------------------------------------|-------------------------------------------|-------------------------------------------| 
| `GET` | `/jwks` | Returns active public keys in JWKS format |
| `POST` | `/auth` | Returns a signed JWT |
| `POST` | `/auth?expired=true` | Returns a JWT signed with an expired key |

---

## **🚀 Installation & Setup**
##  Prerequisites
- [Language] -Python
- [Web Framework] -Flask
- [JWT Library] -PyJWT, jsonwebtoken, etc

STEPS:

### **1️⃣ Clone the Repository**
```basH
git clone https://github.com/yourusername/jwks-server.git
cd jwks-server
```

### **2️⃣ Install dependencies**
```bash
pip install -r requirements.txt
```

### **3️⃣ Run the server**
```bash
python app.py
```

### **4️⃣ Run tests**
```bash
pytest
```

## Testing:
**1. Automated Tests:**

The project includes a test suite to ensure proper functionality. Test coverage is over 80%. To run tests:
```
pytest --cov=app

```

**2. Black-Box Testing:**

A test client was used to verify that:
- The /auth endpoint returns a valid JWT.
- The /auth?expired=true endpoint returns an expired JWT.
- The /jwks endpoint correctly returns only unexpired keys.
- Screenshot of the test client is included in the repo.

---

## ✅ Response Example:

### **Request:** 
To retrieve the JSON Web Key Set (JWKS), run: 
```bash 
curl http://127.0.0.1:8080/.well-known/jwks.json
```
### **Response:** 
```json
{
  "keys": [
    {
      "alg": "RS512",
      "e": "AQAB",
      "kid": "4d2f8e17-7b3f-46a4-a1ff-8a2b8c95f08b",
      "kty": "RSA",
      "n": "vhdL0XQ0Bw5BbJm2YPXLms6BQI48TjHnPzA-1XYpNBubOfXW6XXh10ZzkA9k-W-Tyy2MQ64dQyFhFF1xDfcv2VE0W2dy-2gFMFyb2Qg72jRMYt9jfGh0gmGOzLKt0FfwDjdv5F6vwAq-97NO8H4G4JtOytWo2IBs9O15PYHKObfvXBZbX9PTROV7yM7I_fY_RGH_X7fRPTxjjaDT0HheC8h3D9e6fW8V6myA7HtK2mQoBZ7mlTpkwl9ef9H6OxLlJmjbEdDT4fOot6ypr2lt04ZGZp0hQs6HgSg2Yoql1AkzLw7S-WKYscnEr_T_oz_eQZ2kTTtQ-yj5khIopPH_-3p6TybXCyLKTdoZ3dmU7tx_N0puuIkFEqM-e8z0fqz9hK7XfGqrsfb__B8w6T9HBO41DwXVsPSw5zZtVg0Q",
      "use": "sig"
    }
  ]
}

```
---
## Screenshots

- 📌Test Client Output
- 📌 Test Suite Coverage Report

Screenshots are available in the repository.

---

## ⭐ Future Improvements
- Implement proper user authentication.
- Store keys securely instead of in-memory.
- Add rate limiting & logging for security.
 
---

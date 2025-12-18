# NeuroAuth: Usage-Focused Flow Guide

## Overview

NeuroAuth is a seed-based, client-side cryptographic identity system. The core of the system is a single secret: the **seed phrase**. All cryptographic operations and authentication derive from this seed, which is never shared with the backend.

---

## Core Principle

- **Seed phrase** is generated once at signup.
- From the seed, the client derives:
  - A login hash (for authentication)
  - An AES encryption key (to protect the private key)
  - A PGP key pair (to encrypt/decrypt user data)
- **Security:** The seed phrase and unencrypted private key never leave the client.

---

## Signup Flow

1. **`generateSeedPhrase()`**
   - **When:** At signup, before anything else.
   - **Why:** Creates the user's master secret. All future authentication and encryption depend on this.
   - **Action:** Show the generated seed phrase to the user for safekeeping.

2. **`deriveSeedsHash(seedPhrase)`**
   - **When:** At signup.
   - **Why:** Backend should never receive the seed phrase. Instead, a hash is sent.
   - **Action:** Hash the seed phrase (SHA-256) and send the hash to the backend as the login identifier.

3. **`deriveEncryptionKey(seedPhrase)`**
   - **When:** At signup (with a new random salt).
   - **Why:** To encrypt the private PGP key before storage.
   - **Action:** Use PBKDF2 to derive a secure AES-256 key from the seed phrase and a random salt. The salt is stored on the backend.

4. **`generateKeyPair()`**
   - **When:** Only at signup.
   - **Why:** Each user needs a unique asymmetric key pair for data encryption/decryption.
   - **Action:** Generate a PGP key pair.

5. **`encryptPrivateKey(privateKey, encryptionKey)`**
   - **When:** Immediately after key generation.
   - **Why:** The private key must never be stored in plaintext.
   - **Action:** Encrypt the private key with AES-GCM. Send the encrypted key, IV, and tag to the backend.

6. **`performSignup(seedPhrase)`**
   - **When:** When the user submits the registration form.
   - **What it does:** Orchestrates all the above steps, stores the AES key locally, and ensures only safe data is sent to the backend.

---

## Login Flow

1. **`deriveSeedsHash(seedPhrase)`**
   - **When:** At login.
   - **Why:** The same seed phrase always produces the same login hash, used for authentication.
   - **Action:** Send the hash to the backend for authentication.

2. **`handleSuccessfulLogin(loginResponse, seedPhrase)`**
   - **When:** After backend confirms authentication.
   - **Action:** Store access token, receive encrypted crypto data, re-derive AES key using stored salt, and store the AES key locally.

3. **`decryptPrivateKey(...)`**
   - **When:** After login, whenever the private key is needed.
   - **Why:** Decrypts the private key in memory for use; never stores it in plaintext.

---

## Normal Application Usage (After Login)

- **`encryptAnyData(data)`**
  - **When:** Before storing user data on the backend.
  - **Why:** Ensures all user data is encrypted before leaving the client.
  - **How:** Uses the stored public key to produce PGP-encrypted data.

- **`decryptAnyData(encryptedData)`**
  - **When:** When fetching encrypted data from the backend.
  - **How:** Decrypts the private key using AES, then decrypts user data using PGP.

---

## Logout Flow

- **`logoutUser()`**
  - **When:** When the user logs out.
  - **Why:** Removes all sensitive material from the browser.
  - **Action:** Clears access token, encrypted crypto metadata, and AES encryption key.

---

## Security Guarantees

- The seed phrase and private key are never sent to the backend.
- The private key is always encrypted at rest.
- Decryption happens only on the client, after successful login.

---

## Summary Table

| Function                        | When Used                | Purpose/Action                                                                 |
|----------------------------------|--------------------------|--------------------------------------------------------------------------------|
| `generateSeedPhrase()`          | Signup                   | Create master secret (seed phrase)                                              |
| `deriveSeedsHash(seedPhrase)`   | Signup/Login             | Derive login hash for backend authentication                                    |
| `deriveEncryptionKey(seedPhrase)`| Signup/Login             | Derive AES key for private key encryption/decryption                           |
| `generateKeyPair()`             | Signup                   | Generate PGP key pair                                                          |
| `encryptPrivateKey()`           | Signup                   | Encrypt private key before backend storage                                      |
| `performSignup()`               | Signup                   | Orchestrate signup cryptographic operations                                     |
| `handleSuccessfulLogin()`       | Login                    | Restore session, re-derive keys, prepare for decryption                        |
| `decryptPrivateKey()`           | After login              | Decrypt private key in memory for use                                          |
| `encryptAnyData()`              | After login              | Encrypt user data before sending to backend                                     |
| `decryptAnyData()`              | After login              | Decrypt user data fetched from backend                                          |
| `logoutUser()`                  | Logout                   | Clear all sensitive data from client                                            |

---

For more details, see the code in [`cryptoOperations.js`](cryptoOperations.js).
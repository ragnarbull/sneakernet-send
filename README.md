# Passwordless E2EE Demo

This fork adds support to encrypt & decrypt using multiple security keys with no password.
This uses the PRF (pseudorandom function) extension, which is built on top of the FIDO/CTAP HMAC-secret extension on the hardware side.
You can add as many compatible security keys as you want and use any combination to encrypt/decrypt.
Also allows for the master AES256GCM & master EC-P256 keys to be rotated without having to present each security key. 

## Compatible authenticator/OS/client combos

- YubiKey 5C NFC (Firmware >5.2) / Windows/ [Chrome >116, Edge >118]
- Android Keystore / Android / Chrome >116
- YubiKey 5C NFC (Firmware >5.2) / macOS / Chrome >116

## Process:

1. Page load - generates user properties (userID & userName) and saves them in an object that will contain an encryption package (NB. if you refresh you wipe the saved data and start again...)
2. Register btn - checks PRF extension is supported on the authenticator/client combo and saves the credential ID and the PRF salt
3. Authenticate btn - generates a local EC-P256 keypair, wraps the local private EC-P256 key with a AES256GCM key derived from the PRF output & a HKDF salt, generates master keys (master AES256GCM key and master EC-P256 keypair) then wraps the master key with a AES256GCM key derived from the local EC-P256 public key & master EC-P256 public key 
4. Encrypt & decrypt - saves the ciphertext & IV and displays this or the cleartext
5. Register btn - register 2nd security key
6. Authenticate btn - authenticate 2nd security key: as above and rotates the master key without presenting the other security key(s)
7. Encrypt & decrypt - you can use one security key to encrypt and the other to decrypt, or use the same security keys
8. Rotate - standalone master key rotation - decrypts & re-encrypts the ciphertext ("vault") using the PRF output from any configured security key, for each security key we generate a new master key wrapping key and wrap the master key with it

Must run in a secure context eg. HTTPS or for LiveServer change "http://127.0.0.1" to "localhost".
WebAuthn spec defines user verification ("UV") is "required" for the PRF extension. 
This means that UV is needed for each registration/authentication/encryption/decryption/(standalone) master key rotation operation. TODO: save a session master key in a secure cookie or similar.

## Demo (Created by @MasterKale)

https://sneakernetsend.com
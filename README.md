# secure-communicator
A secure messaging program created in Python using the Pycryptodome library.
Send secure messages over a unsecure network.
Command line program.

TO RUN:
1. Install Python 3.0 or later
2. Install your preferred IDE
3. install the pycryptodome library using the command

       pip install pycryptodome

4. Download communicator.py and run as project
6. Run communicator.py





# Features
## CONFIDENTIALITY
RSA Asymmetric Key encryption
- Allows secure transfer of AES key and nonce seed over an unsecure network via digital envelope

AES Key Encryption (CBC)
- Encrypts message using AES in CBC mode

## INTEGRITY

Nonce usage
- Uses securely transfered seed value to produce deterministic random values, preventing replay attacks

SHA256
- Attaches hashed digest of plaintext to encrypted message. Ensures sent message has not been altered in any way after sending

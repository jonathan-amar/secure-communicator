##
#A program to safely share messages over an unsafe network
#Author(s): Jonathan Amar
#Version: 26 December 2023
##

import os
import socket
import random

import Crypto.Random
from Crypto import Random
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.IO import PEM
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad

MY_KEYS_DIR = "my_key_pairs/"  # Location of private keys
RSA_EXTN = ".rsa"  # RSA key file extension
AES_EXTN = ".aes"  # AES key file extension
RSA_KEY_SIZE = 2048  # 4096 Slow #8192 impossibly slow
AES_KEY_SIZE = 16
BLOCK_SIZE = 16
RECV_SIZE = 1024
MAX_MESSAGE = 4096
TIMEOUT = 30.0
B_END_MESSAGE = b'#<<END>>#'
END_MESSAGE = '#<<END>>#'
PORT = 65432
MAX_RAND = 1000
HASH_INDEX = 32
SEED_PAD_INDEX = 48
SEQUENCE_PAD_INDEX = 64
NONCE_PAD_INDEX = 80
IV_INDEX = 96

def gen_seed():
    '''
    Generates a random integer between 1 and 1000.
    '''
    return random.randint(1,MAX_RAND)

def get_nonce(sequence, seed):
    '''
    Generates a random integer using a seed value and sequence number.

    Args:
        sequence : The sequence number used to generate the nonce value.
        seed : The seed value used to generate the nonce value.

    Returns:
        nonce : The generated nonce value.
    '''

    random.seed(seed)
    for i in range(sequence):
        nonce = random.randint(1, MAX_RAND)
    return nonce


def is_nonce(sequence, seed, nonce):
    '''
    Returns True if the given nonce value matches the result of calling get_nonce() with the given sequence and seed values.

    Args:
        sequence : The sequence number used to generate the nonce value.
        seed : The seed value used to generate the nonce value.
        nonce : The nonce value to check.

    Returns:
        bool: True if the given nonce value matches the result of calling get_nonce() with the given sequence and seed values, False otherwise.
    '''
    return get_nonce(sequence, seed) == nonce


def handle_nonce(my_sequence, seed, recv_nonce):
    '''
    Returns a tuple containing a boolean value indicating whether the given nonce value is valid, the next expected sequence value, and the next nonce value.

    Args:
        my_sequence : The current sequence number.
        seed : The seed value used to generate the nonce value.
        recv_nonce : The received nonce value.

    Returns:
        tuple: A tuple containing a boolean value indicating whether the given nonce value is valid, the next expected sequence value, and the next nonce value.
    '''
    if not is_nonce(my_sequence+1, seed, recv_nonce):
        return (False, 0, 0)
    return (True, my_sequence+2, get_nonce(my_sequence+2, seed))


def list_key_pairs():
    '''
    Prints all files listed in the 'my_key_pairs' directory that have the '.rsa' file extension to the terminal.
    '''
    # If the keys directory does not exist, create it
    if not os.path.exists(MY_KEYS_DIR):
        os.makedirs(MY_KEYS_DIR)
    print("======Own Key Pairs======")
    # Iterate over the files in the keys directory
    for keyPair in os.listdir(MY_KEYS_DIR):
        if keyPair.endswith(".rsa"):
            # Print the file name
            print(keyPair)


def list_public_keys():
    '''
    Prints all files listed in the 'my_key_pairs' directory that have the '_pub.rsa' file extension to the terminal.
    '''
    # If the keys directory does not exist, create it
    if not os.path.exists(MY_KEYS_DIR):
        os.makedirs(MY_KEYS_DIR)
    print("======Public Keys======")
    # Iterate over the files in the keys directory
    for publicKey in os.listdir(MY_KEYS_DIR):
        # If the file ends with "_pub.rsa", it is a public key file
        if publicKey.endswith("_pub.rsa"):
            # Print the file name
            print(publicKey)


def valid_ip(ipv4):
    '''
    Returns a boolean indicating whether the given string is a valid IPv4 address.

    Args:
        ipv4 : The IPv4 address to check.

    Returns:
        bool : True if the given string is a valid IPv4 address, False otherwise.
    '''
    # Split the given IP address by the period (.) character
    nums = ipv4.split('.')
    # If the resulting list does not have 4 items, it is not a valid IPv4 address
    if len(nums) != 4:
        return False
    # For each item in the list, check if it is a valid number between 0 and 255
    for num in nums:
        # If the item is not a number, it is not a valid IPv4 address
        if not num.isdigit():
            return False
        # If the number is not between 0 and 255, it is not a valid IPv4 address
        i = int(num)
        if i < 0 or i > 255:
            return False
    # If the function has not returned by this point, the IP address is valid
    return True


def make_rsa_keys():
    '''
    Takes input from user on key name and creates a secret RSA key of that name.
    Stores key in the 'shared_keys' directory.
    '''
    # Prompt the user to enter a name for the key, and validate the input
    name = input("Enter a name for the key (without file extension): ")
    while name == "":
        name = input("Enter a name for the key (without file extension): ")
    # Check if a file with the given name already exists
    if os.path.isfile(name + "_pub.rsa") or os.path.isfile(name + "_prv.rsa"):
        print("One or more files of this name already exist")
        return
    # If the keys directory does not exist, create it
    if not os.path.exists(MY_KEYS_DIR):
        os.makedirs(MY_KEYS_DIR)
    # Generate a new RSA key pair
    key = RSA.generate(RSA_KEY_SIZE)
    private_key = key
    public_key = key.publickey()
    # Open the public and private key files in binary write mode
    file1 = open(MY_KEYS_DIR + name + "_pub" + RSA_EXTN, "wb")
    file2 = open(MY_KEYS_DIR + name + "_prv" + RSA_EXTN, "wb")
    # Write the keys to the files in PEM format
    file1.write(public_key.exportKey('PEM'))
    file2.write(private_key.exportKey('PEM'))
    # Close the files
    file1.close()
    file2.close()
    print("Key pair created.")


def make_aes_key():
    '''
    Takes input from user on key name and size and creates an AES key of that name.
    Stores key in the 'shared_keys' directory.
    '''
    return Crypto.Random.get_random_bytes(AES_KEY_SIZE)


def is_end_msg(ciphertext, aes_key):
    """
        This function checks whether the given ciphertext is the end of the communication. It does this by decrypting
        the ciphertext using the provided AES key, and checking if the decrypted message matches the end message
        delimiter.

        Args:
            ciphertext: The encrypted message to be checked.
            aes_key: The AES key to use to decrypt the ciphertext.

        Returns:
            A boolean indicating whether the given ciphertext is the end of the communication or not.
        """
    # Separate the digest, encrypted seed, encrypted sequence, encrypted nonce,
    # and initialization vector from the ciphertext
    digest = ciphertext[:HASH_INDEX]
    enc_seed = ciphertext[HASH_INDEX: SEED_PAD_INDEX]
    enc_sequence = ciphertext[SEED_PAD_INDEX:SEQUENCE_PAD_INDEX]
    enc_nonce = ciphertext[SEQUENCE_PAD_INDEX:NONCE_PAD_INDEX]
    iv = ciphertext[NONCE_PAD_INDEX:IV_INDEX]
    ciphertext = ciphertext[IV_INDEX:]

    # Use the AES key to decrypt the seed, sequence, and nonce values using the CBC mode
    aeskey = AES.new(aes_key, AES.MODE_CBC, iv)
    seed = int(unpad(aeskey.decrypt(enc_seed), BLOCK_SIZE).decode('utf-8'))
    sequence = int(unpad(aeskey.decrypt(enc_sequence), BLOCK_SIZE).decode('utf-8'))
    nonce = int(unpad(aeskey.decrypt(enc_nonce), BLOCK_SIZE).decode('utf-8'))
    plaintext = unpad(aeskey.decrypt(ciphertext), BLOCK_SIZE)


    # Check the message integrity by comparing the digest of the plaintext with the original digest
    return plaintext.decode('utf-8') == END_MESSAGE


def decrypt_message(ciphertext, aes_key, my_sequence):
    '''
    Asks user for a key and ciphertext file containing digest, initialization vector, and ciphertext. Parses through the
    file, pulling out the individual contents. Decrypts the ciphertext, and uses the key and IV to compare digests to
    ensure message integrity.
    '''
    # Parse the ciphertext into its individual components
    digest = ciphertext[:HASH_INDEX]
    enc_seed = ciphertext[HASH_INDEX: SEED_PAD_INDEX]
    enc_sequence = ciphertext[SEED_PAD_INDEX:SEQUENCE_PAD_INDEX]
    enc_nonce = ciphertext[SEQUENCE_PAD_INDEX:NONCE_PAD_INDEX]
    iv = ciphertext[NONCE_PAD_INDEX:IV_INDEX]
    ciphertext = ciphertext[IV_INDEX:]

    # Decrypt the ciphertext using the AES key and IV
    aeskey = AES.new(aes_key, AES.MODE_CBC, iv)
    seed = int(unpad(aeskey.decrypt(enc_seed), BLOCK_SIZE).decode('utf-8'))
    sequence = int(unpad(aeskey.decrypt(enc_sequence), BLOCK_SIZE).decode('utf-8'))
    nonce = int(unpad(aeskey.decrypt(enc_nonce), BLOCK_SIZE).decode('utf-8'))
    plaintext = unpad(aeskey.decrypt(ciphertext), BLOCK_SIZE)

    match, new_sequence, new_nonce = handle_nonce(my_sequence, seed, nonce)
    # Check the message integrity by comparing the digest of the plaintext with the original digest
    newhash = SHA256.new(plaintext).digest()
    if newhash == digest and match and sequence == my_sequence+1:
        print("Message received:")
        print(plaintext.decode('utf-8'))
        return True, new_sequence, new_nonce
    else:
        print("Harmful Message received.")
        return False, 0, 0


def encrypt_message(plaintext, key, seed, sequence, nonce):
    """
    Encrypts a plaintext message using the specified key, seed, sequence, and nonce.

    Args:
        plaintext : The plaintext message to encrypt.
        key : The key to use for encrypting the message.
        seed : The seed value to use for encrypting the message.
        sequence : The sequence value to use for encrypting the message.
        nonce : The nonce value to use for encrypting the message.

    Returns:
        bytes: The encrypted message.
    """
    # Create a digest of the plaintext
    digest = SHA256.new(plaintext.encode('utf-8')).digest()
    # Generate a random initialization vector (iv)
    iv = Crypto.Random.get_random_bytes(16)
    # Create a new AES cipher using the given key and iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    # Encrypt the seed, sequence, and nonce values and pad them to the block size
    seed = cipher.encrypt(pad(str(seed).encode('utf-8'), BLOCK_SIZE))
    sequence = cipher.encrypt(pad(str(sequence).encode('utf-8'), BLOCK_SIZE))
    nonce = cipher.encrypt(pad(str(nonce).encode('utf-8'), BLOCK_SIZE))
    # Encrypt the plaintext and pad it to the block size
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), BLOCK_SIZE))
    # Return the concatenated digest, seed, sequence, nonce, iv, and ciphertext
    return digest + seed + sequence + nonce + iv + ciphertext


def encrypt_aes_key_with_rsa(pub_key, aes_key):
    """
    Encrypts the given aes_key with the given pub_key and returns the encrypted AES key, along with the seed,
    sequence, and nonce used in the encryption.

    Args:
        pub_key : The RSA public key to encrypt the AES key with.
        aes_key : The AES key to encrypt.

    Returns:
        Tuple[bytes, int, int, int]: The encrypted AES key, the `seed` used in the encryption,
        the `sequence` used in the encryption, and the `nonce` used in the encryption.
    """
    # Import the RSA public key from a provided string
    pubkey = RSA.importKey(pub_key)
    # Compute a SHA256 digest of the AES key
    aes_digest = SHA256.new(aes_key).digest()
    # Initialize a PKCS1_OAEP object using the RSA public key
    pubkeydigest = PKCS1_OAEP.new(pubkey)
    # Generate a random seed and set sequence number
    seed = gen_seed()
    sequence = 1
    # Compute a nonce using the seed and sequence number
    nonce = get_nonce(sequence, seed)
    # Pad the seed, sequence, and nonce to ensure they are a multiple of the block size
    p_seed = pad(str(seed).encode('utf-8'), BLOCK_SIZE)
    p_sequence = pad(bytes(str(sequence).encode('utf-8')), BLOCK_SIZE)
    p_nonce = pad(bytes(str(nonce).encode('utf-8')), BLOCK_SIZE)
    # Concatenate the SHA256 digest, encrypted seed, sequence, nonce, and AES key
    # and return the result along with the generated seed, sequence, and nonce
    return aes_digest + pubkeydigest.encrypt(p_seed + p_sequence + p_nonce + aes_key), seed, sequence, nonce


def decrypt_aes_key_with_rsa(aes, rsa_key):
    """
    Decrypts an encrypted AES key using an RSA private key.

    Args:
        aes: a byte string containing the encrypted AES key.
        rsa_key: a byte string containing the RSA private key.

    Returns:
        Tuple (key, seed, sequence, nonce, success) where:
        key: a byte string containing the decrypted AES key, or None if the decryption failed.
        seed: an int representing the seed, or None if the decryption failed.
        sequence: an int representing the sequence, or None if the decryption failed.
        nonce: an int representing the nonce used, or None if the decryption failed.
        success: a boolean indicating whether the decryption was successful.
"""
    # Parse the encrypted AES key into its individual components
    olddigest = aes[:HASH_INDEX]
    aes = aes[HASH_INDEX:]
    # Import the private RSA key
    rsa = RSA.importKey(rsa_key)

    # Create a new RSA decrypter
    rsa_key_decrypter = PKCS1_OAEP.new(rsa)

    aes = olddigest + rsa_key_decrypter.decrypt(aes)
    # Separate seed, sequence, and nonce, decode them, and convert them to ints
    seed = int(unpad(aes[HASH_INDEX:SEED_PAD_INDEX], BLOCK_SIZE).decode('utf-8'))
    sequence = int(unpad(aes[SEED_PAD_INDEX:SEQUENCE_PAD_INDEX], BLOCK_SIZE).decode('utf-8'))+1
    nonce = int(unpad(aes[SEQUENCE_PAD_INDEX:NONCE_PAD_INDEX], BLOCK_SIZE).decode('utf-8'))
    key = aes[NONCE_PAD_INDEX:]

    # Check the integrity of the decrypted AES key by comparing the original and new digests
    newdigest = SHA256.new(key).digest()
    if newdigest == olddigest:
        print("Digest matches")
        return key, seed, sequence, get_nonce(sequence, seed), True
    elif not get_nonce(sequence, nonce):
        print("SEED ERROR")
        return None, None, None, None, True
    else:
        print("Digest does not match, ciphertext changed")
        print("original digest = " + olddigest.decode('utf-8'))
        print("new digest = " + newdigest.decode('utf-8'))
        return None, None, None, None, False


def send_loop(s, aes_key, seed, nonce, sequence):
    """
        Sends and receives encrypted messages over a socket using the provided encryption key.

    Args:
        s : The socket to send the messages over.
        aes_key : The key to use for encrypting the messages.
        seed : The seed to use for generating new nonces.
        nonce : The nonce to use to prevent replay attacks.
        sequence : A variable to keep track of the order in which the messages are sent and received.
    """
    # Start a loop that continues until the user decides to stop sending messages or an error occurs
    try:
        # Start by assuming the user wants to send a message
        respond = 'Y'
        # Continue looping as long as the user wants to send messages
        while respond == 'Y':
            # Prompt the user to enter a message
            message = input("Enter message (max length 4096) : ")
            # Check if the message exceeds the maximum allowed length
            # If it does, prompt the user to enter a new message
            while len(message) > MAX_MESSAGE:
                print("Message exceeds maximum length")
                message = input("Enter message (max length 4096) : ")
            # Encrypt the user's message using the AES key and the previously generated seed, sequence, and nonce
            enc_msg = encrypt_message(message, aes_key, seed, sequence, nonce)
            # Send the encrypted message to the other party
            s.sendall(enc_msg)
            # Print a message indicating that the client is waiting for a response from other party
            print("Waiting for message...")
            while True:
                message = s.recv(RECV_SIZE)
                
                if not message:
                    print("Connection closed by the remote side.")
                    break
                break
            # Check if the server's message is an end-of-communication message
            # If it is, close the connection and break out of the loop
            if is_end_msg(message, aes_key):
                s.close()
                print("Connection closed.")
                break
            # Otherwise, decrypt the server's message
            # If the decryption fails, close the connection and break out of the loop
            safe, sequence, nonce = decrypt_message(message, aes_key, sequence)
            if not safe:
                print("Closing Connection.")
                s.sendall(encrypt_message(END_MESSAGE, aes_key, seed, sequence, nonce))
                s.close()
                print("Connection closed.")
                break
            # Prompt the user to decide whether they want to send another message
            respond = response()
        # If the user decided not to send another message,
        # send an end-of-communication message to the server and close the connection
        if respond == 'N':
            print("Closing connection")
            s.sendall(encrypt_message(END_MESSAGE, aes_key, seed, sequence, nonce))
            s.close()
            print("Connection closed.")
    # If any errors occur while sending or receiving messages,
    # send an end-of-communication message to the server and close the connection
    except ValueError:
        print("Error over connection, closing connection")
        s.sendall(encrypt_message(END_MESSAGE, aes_key, seed, sequence, nonce))
        s.close()
        return



def receive_loop(conn, aes_key, seed, sequence, nonce):
    """
        Sends and receives encrypted messages over a socket using the provided encryption key.

    Args:
        conn : The socket to send the messages over.
        aes_key : The key to use for encrypting the messages.
        seed : The seed to use for generating new nonces.
        nonce : The nonce to use to prevent replay attacks.
        sequence : A variable to keep track of the order in which the messages are sent and received.

        Returns:
            None
        """
    try:
        # Wait for a message from the client and decrypt it
        print("Waiting for message...")
        message = conn.recv(1024)
        safe, sequence, nonce = decrypt_message(message, aes_key, sequence)
        # If the decryption fails, close the connection and exit the function
        if not safe:
            print("Closing Connection.")
            conn.sendall(encrypt_message(END_MESSAGE, aes_key, seed, sequence, nonce))
            conn.close()
            print("Connection closed.")
            return
        # Prompt the user to decide whether they want to send a message
        respond = response()
        # If the user wants to send a message, start a loop that continues
        # until the user decides to stop sending messages
        while respond == 'Y':
            # Use a context manager to ensure the connection is closed properly after the loop finishes
            with conn:
                # Prompt the user to enter a message
                message = input("Enter message (Max length 4096) : ")
                # Check if the message exceeds the maximum allowed length
                # If it does, prompt the user to enter a new message
                while len(message) > MAX_MESSAGE:
                    print("ERROR: Message exceeds max length")
                    message = input("Enter message (Max length 4096) : ")
                # Encrypt the user's message using the AES key and the previously generated seed, sequence, and nonce
                enc_msg = encrypt_message(message, aes_key, seed, sequence, nonce)
                # Send the encrypted message to the client
                conn.sendall(enc_msg)
                # Print a message indicating that the server is waiting for a response from the client
                print("Waiting for message...")
                message = conn.recv(RECV_SIZE)
                # Check if the client's message is an end-of-communication message
                # If it is, close the connection and break out of the loop
                if is_end_msg(message, aes_key):
                    conn.close()
                    print("connection closed.")
                    break
                safe, sequence, nonce = decrypt_message(message, aes_key, sequence)
                # Otherwise, decrypt the client's message
                # If the decryption fails, close the connection and break out of the loop
                if not safe:
                    print("Closing Connection.")
                    conn.sendall(encrypt_message(END_MESSAGE, aes_key, seed, sequence, nonce))
                    conn.close()
                    print("Connection closed.")
                    break
            # Prompt the user to decide whether they want to send another message
            respond = response()
        # If the user decided not to send another message,
        # send an end-of-communication message to the client and close the connection
        if respond == 'N':
            print("Closing connection.")
            conn.sendall(encrypt_message(END_MESSAGE, aes_key, seed, sequence, nonce))
            print("Connection closed.")
            conn.close()

    # If any errors occur while sending or receiving messages,
    # send an end-of-communication message to the client and close
    except ValueError:
        print("Error over connection")
        try:
            conn.sendall(encrypt_message(END_MESSAGE, aes_key, seed, sequence, nonce))
        except WindowsError:
            print("Connection already closed on other end")
    except WindowsError:
        print("Error over connection")
        print("The Connection already closed on other end")


def receive_setup():
    """
       Receives encrypted messages over a socket and establishes a symmetric key for further communication.
    """
    # Prompt the user to enter the IP address of the sender (the client)
    ip = input("Enter IP Address of sender (leave empty for all) : ")
    # Check if the IP address is valid or is empty
    # If it is not, prompt the user to enter a new IP address
    while not (valid_ip(ip) or ip == ''):
        print("ERROR: Invalid IPV4 address")
        ip = input("Enter IP Address of sender (leave empty for all) : ")
    # Use a socket to bind to the specified IP address and port and listen for incoming connections
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((ip, PORT))
        print("Waiting for a message on port " + str(PORT))
        s.listen()
        s.settimeout(None)
        # Accept the incoming connection and use a context manager to ensure it is closed properly
        conn, ip = s.accept()
        with conn:
            # Receive the client's public key
            pub_key = conn.recv(RECV_SIZE)
            print("Received public key")
            # Generate a random one-time symmetric key (the AES key)
            print("Generating one-time symmetric key")
            aes = make_aes_key()
            # Hash and encrypt the AES key using the RSA public key
            print("Hashing and Encrypting")
            encrypted_aes_key, seed, sequence, nonce = encrypt_aes_key_with_rsa(pub_key, aes)
            
            # Send the encrypted AES key to the client
            print("Sending symmetric key")
            conn.sendall(bytes(encrypted_aes_key))
            # Call the `send_loop` function to handle sending and receiving messages using the AES key
            receive_loop(conn, aes, seed, sequence, nonce)


def response():
    """
    Prompts the user to enter a response of "Y" or "N".

    Returns:
        respond: The user's response as a string ("Y" or "N").
    """
    respond = input("Respond? Y/N").upper()
    while not (respond == 'Y' or respond == 'N'):
        respond = input("Respond? Y/N")
    return respond


def send_setup():
    """
        Sets up a connection to send encrypted messages to a recipient.
    """
    # List the available public keys and prompt the user to select one
    list_public_keys()
    filename = input("Select public key : ")
    # Check if the selected public key exists
    # If it does not, prompt the user to select a different key
    while not (os.path.isfile(MY_KEYS_DIR + filename + "_pub"+ RSA_EXTN)):
        print("ERROR: Public key does not exist")
        filename = input("Select public key: ")
    # Prompt the user to enter the IP address of the recipient (the server)
    ip = input("Type Recipient IP: ")
    # Check if the IP address is valid
    # If it is not, prompt the user to enter a new IP address
    while not (valid_ip(ip)):
        print("ERROR: Invalid IPV4 address")
        ip = input("Type Recipient IP : ")
    # Open the public key file in read-binary mode and the private key file in read-binary mode
    pub_key_file = open(MY_KEYS_DIR + filename + "_pub" + RSA_EXTN, 'rb')
    prv_key_file = open(MY_KEYS_DIR + filename + "_prv" + RSA_EXTN, 'rb')
    # Use a try-except block to handle any errors that occur while sending the public key or receiving the response
    try:
        # Create a socket and use it to connect to the recipient's IP address and port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Set a timeout on the socket to handle cases where the recipient does not respond
        s.settimeout(TIMEOUT)
        s.connect((ip, PORT))
        s.settimeout(None)
        # Send the public key to the recipient
        print("Sending public key...")
        s.sendall(pub_key_file.read())
        # Wait for the recipient to respond with the encrypted AES key
        print("Waiting...")
        s.settimeout(TIMEOUT)
        aes_key, seed, sequence, nonce, match = decrypt_aes_key_with_rsa(s.recv(RECV_SIZE), prv_key_file.read())
        # If the decryption of the recipient's response fails, close the connection
        if not match:
            s.sendall(B_END_MESSAGE)
            s.close()
            print("Connection Closed.")
        else:
            # If the decryption is successful, print a success message and call the `send_loop` function to handle
            # sending and receiving messages using the AES key
            print("Received symmetric key from " + ip)
            send_loop(s, aes_key, seed, nonce, sequence)
    # If a timeout occurs while sending the public key or receiving the response, print an error message
    except socket.timeout:
        print("Message sending error. Message not sent")


def do_option(option):
    '''Respond to a manu option by calling the appropriate function. If an option
    that is <= 0 and > 7  or not an int is specified, an error message will be printed.
    Parameters:
        option : (int) The selected option.'''
    if option == '1':  # Make keys
        make_rsa_keys()
    elif option == '2':
        list_key_pairs()
    elif option == '3':
        send_setup()
    elif option == '4':
        receive_setup()
    elif option != '0':
        print("Error invalid option.")


def menu():
    print("====The Secure Decryptor=====")
    print("1: Generate RSA Key Pair")
    print("2: View RSA key pairs")
    print("3: Send Message")
    print("4: Receive Message")
    print("0: Exit")


def main():
    menu()
    option = input("Enter Option>")
    while option != "0":
        do_option(option)
        menu()
        option = input("Enter Option>")

    print("Program closed.")


if __name__ == "__main__":
    main()

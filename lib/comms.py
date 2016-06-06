import struct

from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Util import Counter
from Crypto import Random
from Crypto.Random import get_random_bytes

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=True):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = None
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake

        # Create our public & private key
        my_public_key, my_private_key = create_dh_key()
        # Send them our public key
        self.send(bytes(str(my_public_key), "ascii"))
        # Receive their public key
        their_public_key = int(self.recv())

        if self.server:
            # Create the initialization vector
            iv = get_random_bytes(AES.block_size)
            # Send them the initialization vector
            self.send(iv)
        elif self.client:
            # Receive the initialization vector
            iv = self.recv()

        # Convert the iv to an integer. We send the iv as a byte array, as that's
        #     how python wants things sent over a connection
        iv = int.from_bytes(iv, byteorder='big')

        # Calculate the shared secret
        self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
        print("Shared hash: {}".format(self.shared_hash.hexdigest()))

        # Create the counter object for the cipher. Crypto handles the incrementing
        ctr = Counter.new(128, initial_value = iv)

        # Create the cipher
        self.cipher = AES.new(self.shared_hash.digest(), AES.MODE_CTR, counter=ctr)
 
    def send(self, data):
        if self.cipher is not None:
            encrypted_data = self.cipher.encrypt(data)
            
            # Generate the HMAC for sending
            hmac = HMAC.new(self.shared_hash.digest(), encrypted_data, digestmod=SHA256)

            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("HMAC: {}".format(hmac.hexdigest()))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            # Sending unencrypted (done while creating a new encrypted session)
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        
        if self.cipher is not None:
            self.conn.sendall(bytes(hmac.hexdigest(), 'UTF-8'))
        else:
			# Send a dummy variable in the place of the HMAC if it is not needed
            self.conn.sendall(b'BLANKBLANKBLANKBLANKBLANKBLANKBLANKBLANKBLANKBLANKBLANKBLANKBLAN')

        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        pkt_hmac = self.conn.recv(64)

        encrypted_data = self.conn.recv(pkt_len)

        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)

            # HMAC generated for Receiver
            hmac = HMAC.new(self.shared_hash.digest(), encrypted_data, digestmod=SHA256)
            hmac = bytes(hmac.hexdigest(), 'UTF-8')
            
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Received HMAC: {}".format(pkt_hmac))
                print("Calculated HMAC: {}".format(hmac))
                print("Original data: {}".format(data))
                
            # Sender & Receiver HMAC is compared to ensure no tampering is present
            if hmac == pkt_hmac:
                print("MSG: SAFE")
            else:
                # MSG session is terminated once tampering is detected
                print("MSG: NOT SAFE")
                self.conn.close()
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()

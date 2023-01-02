import socket, time, json, os

from random import randint
from base64 import urlsafe_b64encode, urlsafe_b64decode

from src.pow import *
from src.core import *
from src.utils import *
from src.logger import *
from src.opcodes import *
from src.cryptography import *

class Connection:
    def __init__(
        self,
        ip: str,
        port: int,
        sourceid: str,
        sock: socket.socket | None = None,
        sessionid: str | None = None,
        targetid: str | None = None,
        conntype: str = 'in'
        ):
        
        self.ip = ip
        self.port = port
        self.sourceid = sourceid
        self.conntype = conntype

        if not sock: # if no socket is passed, create one
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )
        
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.TCP_NODELAY,
            1
        )

        if not sessionid:
            sessionid = os.urandom(128).hex()
        
        if not sourceid:
            sourceid = 'Unknown ID'
        
        if not targetid:
            targetid = 'Unknown ID'

        self.sock = sock
        self.sessionid = sessionid
        self.sourceid = sourceid
        self.targetid = targetid

        self.pow = Pow(
            Core.hardcoded_pow_difficulty
        ) 

        self.raw = {}
        self.enckey = b''
        self.pubkey = b''
        self.privkey = b''
    
    @property
    def addr(self):
        return f'{self.ip}:{self.port} ({self.targetid})'
    
    @property
    def closed(self):
        return self.sock.fileno() == -1

    def wait_until(
        self,
        opcode: int = opcodes.ack,
        buffer_size: int = 2048,
        timeout: int = 600 # one hour
        ) -> dict[str, str] | None:

        while 1:
            r = self.recv(
                buffer_size,
                timeout
            )

            if not r:
                return None

            r = deserialize(r)
            if r.get('cmd') == opcode:
                return r
        
        return None
    
    def close(
        self
        ) -> bool:

        logging.info(f'Closing connection to {self.addr}')

        Core.peerlist.remove_peer(self)

        self.sock.close()

        return self.closed

    def make_payload(
        self,
        data: dict,
        pad: bool = True
        ) -> bytes:
        '''
        make_payload(raw dictionary, add padding) -> payload

        Turns the dictionary into bytes

        :param data dict: Raw data
        :param pad bool: Add padding
        :returns bytes: Dictionary converted into bytes
        '''

        data.update({
            'sessionid': self.sessionid,
            'sourceid': self.sourceid
        })

        return serialize(
            data, 
            pad=pad
        )
    
    def recv(
        self,
        buffer_size: int = 2048,
        timeout: int | float = 15.0
        ) -> bytes | None:
        '''
        recv(buffer size, timeout) -> received bytes or None

        Listens for incoming data, until the timeout is hit

        :param buffer_size int: Buffer size
        :param timeout int or float: Timeout to wait before stopping
        :returns bytes or None: Received data, None incase of any errors
        '''

        # don't bother listening on a closed socket
        if self.closed:
            logging.warning('Socket is closed!')
            return None

        buffer = b''

        self.sock.settimeout(timeout)
        while 1:
            try:
                r = self.sock.recv(buffer_size)
                if not r or len(r) == 0:
                    return None

                buffer += r

                if r.endswith(b'\r\n\r\n'):
                    break

            except socket.timeout:
                break

            except Exception as exc:
                logging.error(f'Exception occurred: {str(exc).rstrip()}')
                return None

        cleartext = buffer
        if buffer != b'': # make sure we don't try decrypting empty data
            try:

                buffer = buffer.rstrip()
                nonce = buffer[:24]
                tag = buffer[24:][:16]
                ciphertext = buffer[40:]
                
                cleartext = xchacha_decrypt(
                    ciphertext=ciphertext,
                    key=Core.hardcoded_handshake_key,
                    nonce=nonce,
                    tag=tag
                )

                if not cleartext:
                    logging.critical('Failed to decrypt data!')
                    cleartext = None

            except Exception as exc:
                logging.critical(f'Failed to decrypt data: {str(exc).rstrip()}')
                cleartext = None

        return cleartext
    
    def send(
        self, 
        data: dict,
        pad: bool = True,
        encrypt: bool = True
        ) -> bool:
        '''
        send(raw data, add padding) -> status

        Turns the given data into a parsable payload
        and sends it

        :param data dict: Data to be sent
        :param pad bool: Add padding
        :param encrypt bool: Encrypt the data using XChaCha20Poly1305
        :returns bool: True if the data was sent, False if otherwise
        '''

        # don't bother sending over a closed socket
        if self.closed:
            return False
        
        buffer = self.make_payload(
            data,
            pad
        )

        ciphertext = buffer
        nonce = b'0'*24
        tag = b'0'*16
        try:

            if encrypt:
                # encrypt the data
                nonce, ciphertext, tag = xchacha_encrypt(
                    plaintext=buffer,
                    key=Core.hardcoded_handshake_key,
                    nonce=os.urandom(24)
                )

        except Exception as exc:
            logging.critical(f'Failed to encrypt data: {str(exc).rstrip()}')

        ciphertext += b'\r\n\r\n'

        try:
            self.sock.sendall(
                nonce
                + tag
                + ciphertext
            )

            return True

        except Exception as exc:
            logging.critical(f'Failed to send data: {str(exc).rstrip()}')
        
        return False
    
    def connect(
        self,
        retry: int = 5,
        retry_delay: int | float = 2.0
        ) -> bool:
        '''
        connect(retry count, retry delay) -> status

        Connects to the IP and port

        :param retry int: Amount of times to try connecting
        :param retry_delay int or float: Delay between the connections
        :returns bool: True if the connection was successful, False if not
        '''
        
        if Core.peerlist.outtable_full:
            logging.warning('Outgoing connection limit hit! Not connecting')
            return False

        hasconnected = False
        for _ in range(retry):
            try:
                self.sock.connect((
                    self.ip, 
                    self.port
                ))

                hasconnected = True
                Core.peerlist.add_peer(self)

                break

            except Exception:
                pass

            time.sleep(retry_delay)
        
        return hasconnected
import socket

from threading import Thread
from random import randint, uniform

from src.core import *
from src.utils import *
from src.logger import *
from src.connection import *
from src.cryptography import *

class Server:
    def __init__(
        self,
        host: str,
        port: int,
        backlog: int = 0,
        sock: socket.socket | None = None,
        identifier: str | None = None
        ):

        self.host = host
        self.port = port
        self.backlog = backlog

        if not sock:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

            sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_REUSEADDR,
                1
            )
        
        if not identifier:
            identifier = randomid()

        self.sock = sock
        self.identifier = identifier

        self.alive = True
        logging.info('Creating X448 keypair')

        # generates the keys
        # and saves them in the PEM format
        self.privkey, self.pubkey = make_x448_keys()
    
    def pinger(
        self,
        delay: int | float = 40,
        jitter: int = 5
        ) -> None:

        while self.alive:
            droplist = []

            if len(Core.peerlist.all_peers) > 0:

                for conn in Core.peerlist.all_peers:
                    try:
                        cookie = os.urandom(16).hex()

                        conn.send({
                            'cmd': opcodes.ping,
                            'cookie': cookie
                        })

                    except Exception as exc:
                        logging.error(f'Exception while pinging {conn.addr}: {exc}')

                        droplist.append(conn)

                    time.sleep(
                        uniform(1, jitter)
                    )
                
                for badconn in droplist:
                    Core.peerlist.remove_peer(
                        badconn
                    )
            
            else:
                logging.warning('Got no connected peers!')
            
            time.sleep(
                uniform(
                    delay / 2,
                    delay + randint(0, jitter)
                )
            )
    
    def handle_client(
        self, 
        conn: Connection
        ):

        # start a mini-handshake first
        # to set the session id

        session_id = os.urandom(128).hex()
        conn.sessionid = session_id

        conn.send({
            'cmd': opcodes.negotiate_session_id_start,
            'id': session_id
        })

        # before we handshake the client must 
        # perform the proof-of-work phase
        conn.send({
            'cmd': opcodes.pow_start,
            'difficulty': conn.pow.difficulty,
            'payload': conn.pow.payload
        })

        r = conn.wait_until(opcodes.pow_finish)

        # check for invalid data
        # and invalid nonces
        if not r \
            or not r.get('nonce') or not r.get('guess') \
            or not conn.pow.verify(r.get('nonce')):

            logging.warning(f'{conn.addr} failed proof-of-work challenge!')
            return conn.close()
        
        logging.info(f'{conn.addr} finished the proof-of-work challenge')
        while not conn.closed:
            r = conn.recv(timeout=45)
            if not r:
                time.sleep(20)
                continue

            r = deserialize(r)

            if not r.get('cmd'):
                logging.warning('Payload does not have "cmd" key, dropping')
                continue

            if r.get('sourceid'):
                conn.targetid = r['sourceid']
            
            if r.get('sessionid'):
                conn.sessionid = r['sessionid']

            else:
                logging.warning('Payload contains no session id, dropping')
                continue
            
            if conn.sessionid != '' and r['sessionid'] != conn.sessionid:
                logging.warning(f'Payload contains invalid session id, expected "{conn.sessionid}" but got "{r["sessionid"]}"')
                continue

            match r['cmd']:
                case opcodes.handshake_start:
                    logging.info(f'{conn.addr} started handshake, storing public key and sending own public key')

                    # because the payload already contains the pubkey
                    # we can store it
                    conn.pubkey = r['key']

                    conn.send({
                        'cmd': opcodes.handshake_exchange_key,
                        'key': self.pubkey
                    })
                
                case opcodes.handshake_exchange_key: # UNUSED
                    logging.info(f'{conn.addr} sent public key, storing key')
                    conn.pubkey = r['key']
                
                case opcodes.handshake_finish:
                    logging.info(f'Handshake with {conn.addr} finished')

                    # request peers from remote peer
                    conn.send({
                        'cmd': opcodes.request_peerlist
                    })
                
                case opcodes.response_peerlist:
                    peers = r['peers']
                    logging.info(f'{conn.addr} responded with peerlist: {", ".join(peers)}')
                
                case opcodes.request_peerlist:
                    logging.info(f'{conn.addr} requested peerlist, sending')
                    conn.send({
                        'cmd': opcodes.response_peerlist,
                        'peers': Core.peerlist.all_peers
                    })

                case opcodes.pow_start:

                    difficulty, payload = r['difficulty'], r['payload']

                    logging.info(f'Starting proof-of-work challenge. Difficulty: {difficulty}')

                    # update the settings
                    conn.pow.difficulty = int(difficulty)
                    conn.pow.payload = payload

                    guess, nonce = conn.pow.guess()

                    conn.send({
                        'cmd': opcodes.pow_finish,
                        'guess': guess,
                        'nonce': nonce
                    })
                
                case opcodes.ping:

                    cookie = r['cookie']

                    logging.info(f'Got PING, sending PONG with cookie "{cookie}"')
                    
                    conn.send({
                        'cmd': opcodes.pong,
                        'cookie': cookie
                    })
                
                case _:
                    logging.warning(f'Opcode "{r["cmd"]}" not recognized!')
                    continue
    
    def listen(self):

        def __listener():
            self.sock.bind((self.host, self.port))
            self.sock.listen(self.backlog)

            logging.info(f'Listening on {self.host}:{self.port} ({self.identifier})')

            while self.alive:
                try:
                    sock, addr = self.sock.accept()

                    # first, check if we've hit the max amount of incoming connections
                    if Core.peerlist.intable_full:
                        logging.warning('Incoming connection limit hit! Dropping connection')
                        sock.close(); continue

                    # then wrap the sock and addr in a connection object
                    conn = Connection(
                        ip=addr[0],
                        port=addr[1],
                        sourceid=self.identifier,
                        sock=sock,
                        conntype='in'
                    )

                    Core.peerlist.add_peer(conn)

                    logging.info(f'New client connected -> {conn.addr}')

                    Thread(
                        target=self.handle_client,
                        args=(conn,)
                    ).start()
                
                except KeyboardInterrupt:
                    logging.info('Caught CTRL-C, breaking.')
                    break
                
                except Exception as exc:
                    logging.error(f'Exception occurred while handling connection: {str(exc).rstrip()}')
        
        Thread(
            target=__listener
        ).start()

        Thread(
            target=self.pinger
        ).start()
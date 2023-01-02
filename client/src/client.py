import socket

from threading import Thread

from src.pow import *
from src.core import *
from src.utils import *
from src.logger import *
from src.connection import *
from src.cryptography import *

class Client:
    def __init__(
        self,
        bootstrap_peers: list,
        sock: socket.socket | None = None,
        identifier: str | None = None
        ):

        self.bootstrap_peers = bootstrap_peers

        if not sock:
            sock = socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            )

        if not identifier:
            identifier = randomid()
        
        self.sock = sock
        self.identifier = identifier

        logging.info('Creating X448 keypair')
        self.privkey, self.pubkey = make_x448_keys()
    
    def handle_connection(self, conn):
        logging.info('Starting handshake')
        conn.send({
            'cmd': opcodes.handshake_start,
            'key': self.pubkey
        })

        while 1:
            try:
                r = conn.recv()
                if not r:
                    time.sleep(20)
                    continue

                r = deserialize(r)

                if not r.get('cmd'):
                    logging.warning('Payload does not have "cmd" key, dropping')
                    continue

                if r.get('sourceid'):
                    conn.targetid = r['sourceid']
                
                if r['cmd'] == opcodes.negotiate_session_id_start:
                    logging.info(f'Updated session id to {r["id"]}')
                    conn.sessionid = r['id']

                if conn.sessionid != '' and r['sessionid'] != conn.sessionid:
                    logging.warning(f'Payload contains invalid session id, expected "{conn.sessionid}" but got "{r["sessionid"]}"')
                    continue

                match r['cmd']:
                    case opcodes.handshake_start:
                        logging.info(f'{conn.addr} started handshake, storing public key and sending own public key')
                        conn.pubkey = r['key']

                        conn.send({
                            'cmd': opcodes.handshake_finish
                        })

                        logging.info(f'Requesting peerlist from {conn.addr}')
                        conn.send({
                            'cmd': opcodes.request_peerlist
                        })
                    
                    case opcodes.request_peerlist:
                        logging.info(f'{conn.addr} requested peerlist, sending')
                        conn.send({
                            'cmd': opcodes.response_peerlist,
                            'peers': Core.peerlist.all_peers
                        })
                    
                    case opcodes.response_peerlist:
                        peers = r['peers']
                        logging.info(f'{conn.addr} responded with peerlist: {", ".join(peers)}')
                    
                    case opcodes.pow_start:

                        difficulty, payload = r['difficulty'], r['payload']

                        logging.info(f'Starting proof-of-work challenge. Difficulty: {difficulty}')

                        # update the settings
                        conn.pow.difficulty = int(difficulty)
                        conn.pow.payload = payload

                        guess, nonce = conn.pow.guess()

                        logging.info(f'Finished, nonce: {nonce}')

                        conn.send({
                            'cmd': opcodes.pow_finish,
                            'guess': guess,
                            'nonce': nonce
                        })
                    
            except KeyboardInterrupt:
                break

            except Exception as exc:
                logging.error(f'Exception occurred: {str(exc).rstrip()}')

                time.sleep(5) # prevents error spam

        conn.close()

    def initialize(self):
        for peer in self.bootstrap_peers:

            # unpack
            try:
                peer_ip, peer_port, peer_id = peer
            except Exception:
                logging.error(f'Failed to unpack "{peer}')
                continue

            logging.info(f'Connecting to {peer_ip}:{peer_port} ({peer_id})')

            # connect
            conn = Connection(
                ip=peer_ip,
                port=peer_port,
                sourceid=self.identifier,
                targetid=peer_id,
                sock=self.sock,
                conntype='out'
            )

            if conn.connect():
                self.handle_connection(conn)
                
            else:
                logging.error('Connection failed')
                continue
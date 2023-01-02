import sys

from src.core import *
from src.server import *
from src.client import *
from src.opcodes import *
from src.connection import *
from src.cryptography import *

if __name__ == '__main__':
    lport = sys.argv[1] #input('Listening port: ')
    bport = sys.argv[2] #input('Remote bootstrap port: ')

    identifier = randomid()

    serv = Server(
        '0.0.0.0',
        int(lport),
        identifier = identifier
    )

    serv.listen()

    client = Client(
        bootstrap_peers=[
            ('127.0.0.1', int(bport), 'Unknown ID')
        ]
    )

    client.initialize()
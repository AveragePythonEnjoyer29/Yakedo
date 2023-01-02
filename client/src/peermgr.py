import time

from random import choices

from src.core import *
from src.logger import *

def peer_manager():
    while 1:
        time.sleep(6)

        logging.info('Cleaning peer list')
        connections = (Core.connections['in'] + Core.connections['out'])
        if len(connections) <= 0:
            logging.warning('Empty peer list!')
            continue

        # pick 16 random peers to drop
        if len(connections) <= 16: # Can lead to peer poisoning
            logging.info('I only have 16 peers, not dropping anything!')
            continue

        droplist = choices(connections, k=16)

        # test all ips before dropping
        for ip in droplist:
            
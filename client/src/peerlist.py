from src.logger import *

class Peerlist:
    def __init__(self):
        self.peerlist = {
            'in': [],
            'out': []
        }

        self.connections_limit_in = 117
        self.connections_limit_out = 16
    
    @property
    def intable_full(self):
        return len(self.peerlist['in']) >= self.connections_limit_in
    
    @property
    def outtable_full(self):
        return len(self.peerlist['out']) >= self.connections_limit_out

    @property
    def all_peers(self) -> list:
        return (
            self.peerlist['in'] 
            + self.peerlist['out']
        )
    
    def add_peer(
        self,
        conn
        ) -> bool:

        try:

            self.peerlist[
                conn.conntype
            ].append(conn)
            return False

        except Exception:
            return True
    
    def remove_peer(
        self,
        conn
        ) -> bool:

        try:
            self.peerlist[
                conn.conntype
            ].remove(conn)

            return True
        except Exception:
            return False
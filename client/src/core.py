from src.peerlist import *

class Core:
    peerlist = Peerlist()

    # hardcoded base values
    # can change at any time
    hardcoded_pow_difficulty = 4

    # DO NOT CHANGE!
    # WILL BREAK COMMUNICATIONS WITH OLDER CLIENTS
    hardcoded_handshake_key = b'\xe8\xd5\x8e~\xd3>tT\xd9%\xb6\xed\xb3X\x94\x9f\xe3\x1f\x0b\x0f"\xbaH\x15!\xadp\xaa\xac[["'
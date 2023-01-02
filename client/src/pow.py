import time, os, hashlib

from src.utils import *

class Pow:
    def __init__(
        self,
        difficulty: int,
        nonce_threshold: int = 500000
        ):

        self.difficulty = difficulty
        self.threshold = nonce_threshold
        self.time_limit = float(difficulty * 1000)

        self.payload = self.make_payload()
    
    def verify(
        self,
        nonce: int
        ) -> bool:

        if not nonce:
            return False

        timestamp, rand = self.payload.split(':')

        # time_limit is (difficulty * 1000)
        ts_min = float(timestamp) - self.time_limit
        ts_max = float(timestamp) + self.time_limit
        ts_now = time.time()

        # discard old and invalid payloads
        if not in_range(ts_now, ts_min, ts_max) or len(rand) != 64:
            return False

        return self.make_hash(
            self.payload+str(nonce)
        ).startswith(self.pattern)
    
    def guess(
        self
        ) -> tuple[str, int]:

        nonce = 0; guess = ''
        while nonce < self.threshold:
            guess = self.make_hash(
                self.payload+str(nonce)
            )

            #print(f'Guess => {guess} && Difficulty: {self.difficulty} && Nonce => {nonce}')
            if guess.startswith(self.pattern):
                break

            nonce += 1

        return guess, nonce

    def make_hash(
        self,
        message: str
        ) -> str:

        return hashlib.sha512(
            message.encode()
        ).hexdigest()

    def make_payload(self) -> str:
        return f'{time.time()}:{os.urandom(32).hex()}'

    @property
    def pattern(self):
        return '0' * self.difficulty
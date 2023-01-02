import time, json

from uuid import uuid4
from random import choices, randint
from base64 import urlsafe_b64decode, urlsafe_b64encode

from src.logger import *

def in_range(
    current: int | float, 
    start: int | float, 
    end: int | float
    ) -> bool:
    return start <= current <= end

def serialize(
    raw: dict, 
    pad: bool = True
    )-> bytes:

    data = {}
    if pad:
        for _ in range(randint(1, 6)):
            name = randomstr(randint(2, 16))
            padding = randomstr(
                randint(64, 256)
            )

            data[name] = padding

    for key, value in raw.items():
  
        if isinstance(value, bytes):
            value = f'B64:{urlsafe_b64encode(value).decode()}'
        else:
            value = value

        data[key] = value
    
    return json.dumps(
        data,
        skipkeys=True,
        ensure_ascii=False,
        check_circular=False
    ).encode()

def deserialize(raw: bytes) -> dict[str, str]:
    try:
        raw = json.loads(
            raw.rstrip(b'\r\n\r\n')
        )
    except Exception as exc:
        logging.error(f'Failed to deserialize data: {str(exc).rstrip()}')
        return {}

    final = {}
    for key, value in raw.items():

        if isinstance(value, str) and value.startswith('B64:'):
            value = urlsafe_b64decode(value[4:])

            try: value = value.decode()
            except Exception: value = value

        final[key] = value
    
    return final

def randomid():
    return str(uuid4())

def randomstr(
    length: int, 
    chars: str | list = 'qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789'
    ) -> str:
    '''
    randomstr(length, allowed characters) -> random string

    Creates a random string from the given characters

    :param length int: Length of the string
    :param chars str or list: Allowed characters
    :returns str: The newly created string
    '''

    return "".join(choices(chars, k=length))
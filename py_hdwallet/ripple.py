from hashlib import sha256
from binascii import hexlify
import six

class RippleBaseDecoder(object):
    """Decodes Ripple's base58 alphabet.
    This is what ripple-lib does in ``base.js``.
    """

    alphabet = 'rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz'

    @classmethod
    def decode(cls, *a, **kw):
        """Apply base58 decode, verify checksum, return payload.
        """
        decoded = cls.decode_base(*a, **kw)
        assert cls.verify_checksum(decoded)
        payload = decoded[:-4] # remove the checksum
        payload = payload[1:]  # remove first byte, a version number
        return payload

    @classmethod
    def decode_base(cls, encoded, pad_length=None):
        """Decode a base encoded string with the Ripple alphabet."""
        n = 0
        base = len(cls.alphabet)
        for char in encoded:
            n = n * base + cls.alphabet.index(char)
        return to_bytes(n, pad_length, 'big')

    @classmethod
    def verify_checksum(cls, bytes):
        """These ripple byte sequences have a checksum builtin.
        """
        valid = bytes[-4:] == sha256(sha256(bytes[:-4]).digest()).digest()[:4]
        return valid

    @staticmethod
    def as_ints(bytes):
        return list([ord(c) for c in bytes])

    @classmethod
    def encode(cls, data):
        """Apply base58 encode including version, checksum."""
        version = b'\x00'
        bytes = version + data
        bytes += sha256(sha256(bytes).digest()).digest()[:4]   # checksum
        return cls.encode_base(bytes)

    @classmethod
    def encode_seed(cls, data):
        """Apply base58 encode including version, checksum."""
        version = bytearray([33])
        bytes = version + data
        bytes += sha256(sha256(bytes).digest()).digest()[:4]   # checksum
        return cls.encode_base(bytes)

    @classmethod
    def encode_base(cls, data):
        # https://github.com/jgarzik/python-bitcoinlib/blob/master/bitcoin/base58.py
        # Convert big-endian bytes to integer
        n = int(hexlify(data).decode('utf8'), 16)

        # Divide that integer into base58
        res = []
        while n > 0:
            n, r = divmod(n, len(cls.alphabet))
            res.append(cls.alphabet[r])
        res = ''.join(res[::-1])

        # Encode leading zeros as base58 zeros
        czero = 0 if six.PY3 else b'\x00'
        pad = 0
        for c in data:
            if c == czero:
                pad += 1
            else:
                break
        return cls.alphabet[0] * pad + res
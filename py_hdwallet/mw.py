#!/usr/bin/env python
import hashlib
import os
import sys
from binascii import hexlify
from getpass import getpass
from optparse import OptionParser

import hashprint
import sha3
from mnemonic.mnemonic import Mnemonic
from pycoin.contrib.segwit_addr import bech32_encode, convertbits
from pycoin.encoding import b2a_hashed_base58, to_bytes_32
from pycoin.key.BIP32Node import BIP32Node

# from .colorize import colorize
from .ripple import RippleBaseDecoder

# mw 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' TREZOR
# > seed c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04
# ku H:$SEED
# > master xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF
# ku -s "44'/0'/0'/0/0" H:$SEED
# > 1PEha8dk5Me5J1rZWpgqSt5F4BroTBLS5y
VISUALIZATION_PATH = "9999'/9999'"

ripple_decoder = RippleBaseDecoder()


def btc_to_address(prefix, subkey):
    return b2a_hashed_base58(prefix + subkey.hash160())


def btc_to_private(exponent):
    return b2a_hashed_base58(b'\x80' + to_bytes_32(exponent) + b'\01')


def eth_to_address(prefix, subkey):
    hasher = sha3.keccak_256()
    hasher.update(subkey.sec(True)[1:])
    return hexlify(hasher.digest()[-20:]).decode()


def eth_to_private(exponent):
    return hexlify(to_bytes_32(exponent)).decode()


def xrp_to_address(prefix, subkey):
    return ripple_decoder.encode(subkey.hash160())


def xrp_to_private(exponent):
    return hexlify(to_bytes_32(exponent)).decode()


def cosmos_to_address(prefix, subkey):
    return bech32_encode(prefix.decode(), convertbits(subkey.hash160(), 8, 5))


def cosmos_to_private(exponent):
    return hexlify(to_bytes_32(exponent)).decode()


coin_map = {
    "btc": (b'\0', "44'/0'/0'/0", btc_to_address, btc_to_private),
    "zcash": (b'\x1c\xb8', "44'/1893'/0'/0", btc_to_address, btc_to_private),
    "eth": (b'', "44'/60'/0'/0", eth_to_address, eth_to_private),
    "rop": (b'', "44'/1'/0'/0", eth_to_address, eth_to_private),
    "xrp": (b'', "44'/144'/0'/0", xrp_to_address, xrp_to_private),
    "txrp": (b'', "44'/1'/0'/0", xrp_to_address, xrp_to_private),
    "cosmos": (b'cosmos', "44'/118'/0'/0", cosmos_to_address, cosmos_to_private),
}

coins = list(coin_map.keys())

coin_list = ",".join(coins)


def mnemonic_to_master(mnemonic, passphrase):
    seed = Mnemonic.to_seed(mnemonic, passphrase=passphrase)
    master = BIP32Node.from_master_secret(seed)
    return seed, master


def compute_address(coin, master, i):
    (address_prefix, coin_derivation, to_address, to_private) = coin_map[coin]
    path = coin_derivation + "/%d"%(i,)
    subkey = next(master.subkeys(path))
    private = to_private(subkey.secret_exponent())
    address = to_address(address_prefix, subkey)
    return address, private, path


def generate(data=None):
    if data is None:
        data = os.urandom(16)
    return Mnemonic('english').to_mnemonic(data)


def hash_entropy(entropy_string):
    ee = hashlib.sha256(entropy_string.encode('utf-8'))
    return ee.digest()[0:16]


def visual(master):
    subkey = next(master.subkeys(VISUALIZATION_PATH))
    return hashprint.pformat(list(bytearray(subkey.hash160())))
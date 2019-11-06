#!/usr/bin/env python
# -*- coding: utf-8 -*-

from datetime import datetime
from pywallet.utils import (
    Wallet, HDPrivateKey, HDKey
)
from pywallet.network import *
import inspect
from .mw import compute_address, mnemonic_to_master
from seed_phrases_for_stellar.seed_phrase_to_stellar_keys import to_binary_seed
from seed_phrases_for_stellar.key_derivation import account_keypair

my_language = 'english'
STELLAR_ACCOUNT_PATH_FORMAT = "m/44'/148'/%d'"
public_stellar_passphrase = 'Public Global Stellar Network ; September 2015'
test_stellar_passphrase = 'Test SDF Network ; September 2015'


def generate_mnemonic(strength=128):
    """

    :param strength:
    :return:
    """
    _, seed = HDPrivateKey.master_key_from_entropy(strength=strength)
    return seed


def generate_child_id():
    """

    :return:
    """
    now = datetime.now()
    seconds_since_midnight = (now - now.replace(
        hour=0, minute=0, second=0, microsecond=0)).total_seconds()
    return int((int(now.strftime(
        '%y%m%d')) + seconds_since_midnight*1000000) // 100)


def create_address(network='btctest', xpub=None, child=None, path=0):
    """

    :param network:
    :param xpub:
    :param child:
    :param path:
    :return:
    """
    assert xpub is not None

    if child is None:
        child = generate_child_id()

    if network == 'ethereum' or network.upper() == 'ETH':
        acct_pub_key = HDKey.from_b58check(xpub)

        keys = HDKey.from_path(
            acct_pub_key, '{change}/{index}'.format(change=path, index=child))

        res = {
            "path": "m/" + str(acct_pub_key.index) + "/" + str(keys[-1].index),
            "bip32_path": "m/44'/60'/0'/" + str(acct_pub_key.index) + "/" + str(keys[-1].index),
            "address": keys[-1].address(),
            "private_key": keys[-1]._key.to_hex()
        }

        if inspect.stack()[1][3] == "create_wallet":
            res["xpublic_key"] = keys[-1].to_b58check()

        return res

    # else ...
    wallet_obj = Wallet.deserialize(xpub, network=network.upper())
    child_wallet = wallet_obj.get_child(child, is_prime=False)

    net = get_network(network)

    return {
        "path": "m/" + str(wallet_obj.child_number) + "/" +str(child_wallet.child_number),
        "bip32_path": net.BIP32_PATH + str(wallet_obj.child_number) + "/" +str(child_wallet.child_number),
        "address": child_wallet.to_address(),
        "private_key": child_wallet.get_private_key_hex(),
        # "xpublic_key": child_wallet.serialize_b58(private=False),
        # "wif": child_wallet.export_to_wif() # needs private key
    }


def get_network(network='btctest'):
    """

    :param network:
    :return:
    """
    network = network.lower()

    if network == "bitcoin_testnet" or network == "btctest":
        return BitcoinTestNet
    elif network == "bitcoin" or network == "btc":
        return BitcoinMainNet
    elif network == "dogecoin" or network == "doge":
        return DogecoinMainNet
    elif network == "dogecoin_testnet" or network == "dogetest":
        return DogecoinTestNet
    elif network == "litecoin" or network == "ltc":
        return LitecoinMainNet
    elif network == "litecoin_testnet" or network == "ltctest":
        return LitecoinTestNet
    elif network == "bitcoin_cash" or network == "bch":
        return BitcoinCashMainNet
    elif network == "bitcoin_gold" or network == "btg":
        return BitcoinGoldMainNet
    elif network == "dash":
        return DashMainNet
    elif network == "dash_testnet" or network == 'dashtest':
        return DashTestNet
    elif network == 'omni':
        return OmniMainNet
    elif network == 'omni_testnet':
        return OmniTestNet
    elif network == "feathercoin" or network == 'ftc':
        return FeathercoinMainNet
    elif network == "qtum":
        return QtumMainNet
    elif network == "qtum_testnet" or network == "qtumtest":
        return QtumTestNet

    return BitcoinTestNet


def create_wallet(network='btctest', seed=None, children=1):
    """

    :param network:
    :param seed:
    :param children:
    :return:
    """
    if seed is None:
        seed = generate_mnemonic()

    net = get_network(network)
    wallet = {
        "coin": net.COIN,
        "seed": seed,
        "private_key": "",
        "public_key": "",
        "xprivate_key": "",
        "xpublic_key": "",
        "address": "",
        "wif": "",
        "children": []
    }

    if network == 'ethereum' or network.upper() == 'ETH':
        wallet["coin"] = "ETH"

        master_key = HDPrivateKey.master_key_from_mnemonic(seed)
        root_keys = HDKey.from_path(master_key, "m/44'/60'/0'")

        acct_priv_key = root_keys[-1]
        acct_pub_key = acct_priv_key.public_key

        wallet["private_key"] = acct_priv_key.to_hex()
        wallet["public_key"] = acct_pub_key.to_hex()
        wallet["xprivate_key"] = acct_priv_key.to_b58check()
        wallet["xpublic_key"] = acct_pub_key.to_b58check()

        child_wallet = create_address(
            network=network.upper(), xpub=wallet["xpublic_key"],
            child=0, path=0)
        wallet["address"] = child_wallet["address"]
        wallet["xpublic_key_prime"] = child_wallet["xpublic_key"]

        # get public info from first prime child
        for child in range(children):
            child_wallet = create_address(
                network=network.upper(), xpub=wallet["xpublic_key"],
                child=child, path=0
            )
            wallet["children"].append({
                "address": child_wallet["address"],
                "private_key": child_wallet["private_key"],
                "xpublic_key": child_wallet["xpublic_key"],
                "path": "m/" + str(child),
                "bip32_path": "m/44'/60'/0'/" + str(child),
            })
    elif network == 'ripple' or network.upper() == 'XRP':
        wallet["coin"] = "XRP"
        (seed, master) = mnemonic_to_master(seed, '')
        (address, private_key, path) = compute_address('xrp', master, 0)

        wallet["private_key"] = private_key
        wallet["public_key"] = address
        wallet["address"] = address

        # get public info from first prime child
        for child in range(children):
            (child_address, child_private_key, child_path) = compute_address('xrp', master, child)
            wallet["children"].append({
                "address": child_address,
                "private_key": child_private_key,
                # "xpublic_key": child_wallet["xpublic_key"],
                "path": "m/" + str(child),
                "bip32_path": child_path,
            })
    elif network == 'zcash' or network.upper() == 'ZCASH':
        wallet["coin"] = "ZCASH"
        (seed, master) = mnemonic_to_master(seed, '')
        (address, private_key, path) = compute_address('zcash', master, 0)

        wallet["private_key"] = private_key
        wallet["public_key"] = address
        wallet["address"] = address

        # get public info from first prime child
        for child in range(children):
            (child_address, child_private_key, child_path) = compute_address('zcash', master, child)
            wallet["children"].append({
                "address": child_address,
                "private_key": child_private_key,
                # "xpublic_key": child_wallet["xpublic_key"],
                "path": "m/" + str(child),
                "bip32_path": child_path,
            })
    elif network == 'stellar_testnet':
        (binary_seed, seed_phrase_type) = to_binary_seed(seed, test_stellar_passphrase, my_language)
        keypair = account_keypair(binary_seed, 0)
        wallet["private_key"] = keypair.seed().decode("utf-8")
        wallet["public_key"] = keypair.address().decode("utf-8")
        wallet["address"] = keypair.address().decode("utf-8")
        # get public info from first prime child
        for child in range(children):
            keypair = account_keypair(binary_seed, child)
            wallet["children"].append({
                "address": keypair.address().decode("utf-8"),
                "private_key": keypair.seed().decode("utf-8"),
                "path": "m/" + str(child),
                "bip39_path": STELLAR_ACCOUNT_PATH_FORMAT % child,
            })
    elif network == 'stellar' or network.upper() == 'XLM':
        (binary_seed, seed_phrase_type) = to_binary_seed(seed, public_stellar_passphrase, my_language)
        keypair = account_keypair(binary_seed, 0)
        wallet["private_key"] = keypair.seed().decode("utf-8")
        wallet["public_key"] = keypair.address().decode("utf-8")
        wallet["address"] = keypair.address().decode("utf-8")
        # get public info from first prime child
        for child in range(children):
            keypair = account_keypair(binary_seed, child)
            wallet["children"].append({
                "address": keypair.address().decode("utf-8"),
                "private_key": keypair.seed().decode("utf-8"),
                "path": "m/" + str(child),
                "bip39_path": STELLAR_ACCOUNT_PATH_FORMAT % child,
            })
    else:
        my_wallet = Wallet.from_master_secret(
            network=network.upper(), seed=seed)

        # account level
        wallet["private_key"] = my_wallet.private_key.get_key().decode()
        wallet["public_key"] = my_wallet.public_key.get_key().decode()
        wallet["xprivate_key"] = my_wallet.serialize_b58(private=True)
        wallet["xpublic_key"] = my_wallet.serialize_b58(private=False)
        wallet["address"] = my_wallet.to_address()
        wallet["wif"] = my_wallet.export_to_wif()

        prime_child_wallet = my_wallet.get_child(0, is_prime=True)
        wallet["xpublic_key_prime"] = prime_child_wallet.serialize_b58(private=False)

        # prime children
        for child in range(children):
            child_wallet = my_wallet.get_child(child, is_prime=False, as_private=True)
            wallet["children"].append({
                "xpublic_key": child_wallet.serialize_b58(private=False),
                "xprivate_key": child_wallet.serialize_b58(private=True),
                "address": child_wallet.to_address(),
                "private_key": child_wallet.get_private_key_hex(),
                "path": "m/" + str(child),
                "bip32_path": net.BIP32_PATH + str(child_wallet.child_number),
            })

    return wallet


def create_wallet(network='btctest', seed=None, children=1):
    """

    :param network:
    :param seed:
    :param children:
    :return:
    """
    if seed is None:
        seed = generate_mnemonic()

    net = get_network(network)
    wallet = {
        "coin": net.COIN,
        "seed": seed,
        "private_key": "",
        "public_key": "",
        "xprivate_key": "",
        "xpublic_key": "",
        "address": "",
        "wif": "",
        "children": []
    }

    if network == 'ethereum' or network.upper() == 'ETH':
        wallet["coin"] = "ETH"

        master_key = HDPrivateKey.master_key_from_mnemonic(seed)
        root_keys = HDKey.from_path(master_key, "m/44'/60'/0'")

        acct_priv_key = root_keys[-1]
        acct_pub_key = acct_priv_key.public_key

        wallet["private_key"] = acct_priv_key.to_hex()
        wallet["public_key"] = acct_pub_key.to_hex()
        wallet["xprivate_key"] = acct_priv_key.to_b58check()
        wallet["xpublic_key"] = acct_pub_key.to_b58check()

        child_wallet = create_address(
            network=network.upper(), xpub=wallet["xpublic_key"],
            child=0, path=0)
        wallet["address"] = child_wallet["address"]
        wallet["xpublic_key_prime"] = child_wallet["xpublic_key"]

        # get public info from first prime child
        for child in range(children):
            child_wallet = create_address(
                network=network.upper(), xpub=wallet["xpublic_key"],
                child=child, path=0
            )
            wallet["children"].append({
                "address": child_wallet["address"],
                "private_key": child_wallet["private_key"],
                "xpublic_key": child_wallet["xpublic_key"],
                "path": "m/" + str(child),
                "bip32_path": "m/44'/60'/0'/" + str(child),
            })
    elif network == 'ripple' or network.upper() == 'XRP':
        wallet["coin"] = "XRP"
        (seed, master) = mnemonic_to_master(seed, '')
        (address, private_key, path) = compute_address('xrp', master, 0)

        wallet["private_key"] = private_key
        wallet["public_key"] = address
        wallet["address"] = address

        # get public info from first prime child
        for child in range(children):
            (child_address, child_private_key, child_path) = compute_address('xrp', master, child)
            wallet["children"].append({
                "address": child_address,
                "private_key": child_private_key,
                # "xpublic_key": child_wallet["xpublic_key"],
                "path": "m/" + str(child),
                "bip32_path": child_path,
            })
    elif network == 'zcash' or network.upper() == 'ZCASH':
        wallet["coin"] = "ZCASH"
        (seed, master) = mnemonic_to_master(seed, '')
        (address, private_key, path) = compute_address('zcash', master, 0)

        wallet["private_key"] = private_key
        wallet["public_key"] = address
        wallet["address"] = address

        # get public info from first prime child
        for child in range(children):
            (child_address, child_private_key, child_path) = compute_address('zcash', master, child)
            wallet["children"].append({
                "address": child_address,
                "private_key": child_private_key,
                # "xpublic_key": child_wallet["xpublic_key"],
                "path": "m/" + str(child),
                "bip32_path": child_path,
            })
    elif network == 'stellar_testnet':
        (binary_seed, seed_phrase_type) = to_binary_seed(seed, test_stellar_passphrase, my_language)
        keypair = account_keypair(binary_seed, 0)
        wallet["private_key"] = keypair.seed().decode("utf-8")
        wallet["public_key"] = keypair.address().decode("utf-8")
        wallet["address"] = keypair.address().decode("utf-8")
        # get public info from first prime child
        for child in range(children):
            keypair = account_keypair(binary_seed, child)
            wallet["children"].append({
                "address": keypair.address().decode("utf-8"),
                "private_key": keypair.seed().decode("utf-8"),
                "path": "m/" + str(child),
                "bip39_path": STELLAR_ACCOUNT_PATH_FORMAT % child,
            })
    elif network == 'stellar' or network.upper() == 'XLM':
        (binary_seed, seed_phrase_type) = to_binary_seed(seed, public_stellar_passphrase, my_language)
        keypair = account_keypair(binary_seed, 0)
        wallet["private_key"] = keypair.seed().decode("utf-8")
        wallet["public_key"] = keypair.address().decode("utf-8")
        wallet["address"] = keypair.address().decode("utf-8")
        # get public info from first prime child
        for child in range(children):
            keypair = account_keypair(binary_seed, child)
            wallet["children"].append({
                "address": keypair.address().decode("utf-8"),
                "private_key": keypair.seed().decode("utf-8"),
                "path": "m/" + str(child),
                "bip39_path": STELLAR_ACCOUNT_PATH_FORMAT % child,
            })
    else:
        my_wallet = Wallet.from_master_secret(
            network=network.upper(), seed=seed)

        # account level
        wallet["private_key"] = my_wallet.private_key.get_key().decode()
        wallet["public_key"] = my_wallet.public_key.get_key().decode()
        wallet["xprivate_key"] = my_wallet.serialize_b58(private=True)
        wallet["xpublic_key"] = my_wallet.serialize_b58(private=False)
        wallet["address"] = my_wallet.to_address()
        wallet["wif"] = my_wallet.export_to_wif()

        prime_child_wallet = my_wallet.get_child(0, is_prime=True)
        wallet["xpublic_key_prime"] = prime_child_wallet.serialize_b58(private=False)

        # prime children
        for child in range(children):
            child_wallet = my_wallet.get_child(child, is_prime=False, as_private=True)
            wallet["children"].append({
                "xpublic_key": child_wallet.serialize_b58(private=False),
                "xprivate_key": child_wallet.serialize_b58(private=True),
                "address": child_wallet.to_address(),
                "private_key": child_wallet.get_private_key_hex(),
                "path": "m/" + str(child),
                "bip32_path": net.BIP32_PATH + str(child_wallet.child_number),
            })

    return wallet

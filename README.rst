py_hd_wallet
===========

** A multi crypto-currencies HD wallet implemented by Python. **

BIP32 (or HD for "hierarchical deterministic") wallets allow you to create
child wallets which can only generate public keys and don't expose a
private key to an insecure server.
The implementation is based on the proposal BIP32, BIP39 and is currently in audit mode.
Please do not use in production yet. Testing welcome.

This library simplify the process of creating new wallets for the
BTC, BTG, BCH, ETH, LTC, DASH, DOGE, ZEC, XRP, ZCASH and XLM.

Most of the code here is copied from:

- Ran Aroussi's `pywallet <https://github.com/ranaroussi/pywallet>`
- Devrandom's `pymultiwallet <https://github.com/devrandom/pymultiwallet>`
- Reverbel's `seed-phrases-for-stellar <https://github.com/reverbel/seed-phrases-for-stellar>`

I simply added support for a few more crypto-currencies.

--------------

Installation
-------------

Install via PiP:

.. code:: bash

   $ sudo pip install py_hd_wallet


Example code:
=============

Create HD Wallet
----------------

The following code creates a new Bitcoin HD wallet:

.. code:: python

    # create_btc_wallet.py

    from py_hd_wallet import wallet

    # generate 12 word mnemonic seed
    seed = wallet.generate_mnemonic()

    # create bitcoin wallet
    w = wallet.create_wallet(network="bitcoin", seed=seed, children=1)
    print(w)

    # wallets = wallet.create_wallet(network="BTC", seed=seed, children=1)
    # wallets = wallet.create_wallet(network="ETH", seed=seed, children=1)
    # wallets = wallet.create_wallet(network="XRP", seed=seed, children=1)
    # wallets = wallet.create_wallet(network="ZCASH", seed=seed, children=1)
    # wallets = wallet.create_wallet(network="XLM", seed=seed, children=1)
    # wallets = wallet.create_wallet(network="stellar_testnet", seed=seed, children=1)

Output looks like this:

.. code:: bash

    $ python create_btc_wallet.py

    {
      "coin": "BTC",
      "seed": "guess tiny intact poet process segment pelican bright assume avocado view lazy",
      "address": "1HwPm2tcdakwkTTWU286crWQqTnbEkD7av",
      "xprivate_key": "xprv9s21ZrQH143K2Dizn667UCo9oYPdTPSMWq7D5t929aXf1kfnmW79CryavzBxqbWfrYzw8jbyTKvsiuFNwr1JL2qfrUy2Kbwq4WbBPfxYGbg",
      "xpublic_key": "xpub661MyMwAqRbcEhoTt7d7qLjtMaE7rrACt42otGYdhv4dtYzwK3RPkfJ4nEjpFQDdT8JjT3VwQ3ZKjJaeuEdpWmyw16sY9SsoY68PoXaJvfU",
      "wif": "L1EnVJviG6jR2oovFbfxZoMp1JknTACKLzsTKqDNUwATCWpY1Fp4",
      "children": [{
         "address": "1nDWAr2v1wNv6ZkjQ3GJCZq1HUHCHm1wZ",
        "address": "1nDWAr2v1wNv6ZkjQ3GJCZq1HUHCHm1wZ",
         "path": "m/0",
         "wif": "KysRDiwJNkS9VPzy1UH76DrCDizsWKtEooSzikich792RVzcUaJP"
     }]
    }


\* Valid options for `network` are: BTC, BTG, BCH, LTC, DASH, DOGE, XRP, ZCASH and XLM



import os, sys
from os.path import dirname, join, abspath
sys.path.insert(0, abspath(join(dirname(__file__), '..')))
from py_hdwallet import wallet

# generate 12 word mnemonic seed
# seed = wallet.generate_mnemonic()
seed = 'guess tiny intact poet process segment pelican bright assume avocado view lazy'
print(seed)

# create bitcoin wallet
wallets = wallet.create_wallet(network="BTC", seed=seed, children=1)
print(wallets)
#
# # create ethereum wallet
wallets = wallet.create_wallet(network="ETH", seed=seed, children=1)
print(wallets)
#
# # create ripple wallet
wallets = wallet.create_wallet(network="XRP", seed=seed, children=1)
print(wallets)

# create zcash wallet
wallets = wallet.create_wallet(network="ZCASH", seed=seed, children=1)
print(wallets)

# # create stellar wallet
wallets = wallet.create_wallet(network="XLM", seed=seed, children=1)
print(wallets)

# # create stellar wallet
wallets = wallet.create_wallet(network="stellar_testnet", seed=seed, children=1)
print(wallets)

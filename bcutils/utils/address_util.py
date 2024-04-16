# -*- coding: utf-8 -*-

from eth_account import Account
from hdwallet import HDWallet
from hdwallet.symbols import BTC, BTCTEST


def eth_account_from_mnemonic(mnemonic):
    Account.enable_unaudited_hdwallet_features()
    account = Account.from_mnemonic(mnemonic)
    address = account.address
    private_key = account.key.hex()
    return {"address": address, "privkey": private_key}


def btc_mnemonic_to_root_xprivkey(mnemonic, testnet=True):
    wallet = HDWallet(BTCTEST if testnet else BTC)
    wallet = wallet.from_mnemonic(mnemonic)
    return wallet.root_xprivate_key()


def btc_address_detecter(address):
    if address.startswith("bc1"):
        if address.startswith("bc1p"):
            if len(address) != 62:
                raise ValueError("P2tr Address Length Error[{address}]")
            return "P2trAddress"
        elif address.startswith("bc1q"):
            if len(address) == 42:
                return "P2wpkhAddress"
            elif len(address) == 62:
                return "P2wshAddress"
            else:
                raise ValueError("SegwitV0 Address Length Error[{address}]")
        else:
            raise ValueError("Segwit Address Format Error[{address}]")
    elif address.startswith("1"):
        if len(address) != 34:
            raise ValueError("Legacy Address Length Error[{address}]")
        return "P2pkhAddress"
    elif address.startswith("3"):
        if len(address) != 34:
            raise ValueError("P2sh Address Length Error[{address}]")
        return "P2shAddress"
    elif address.startswith("tb1"):
        if len(address) == 42:
            return "P2wpkhAddress"
        elif len(address) == 62:
            return "P2trAddress"
        else:
            raise ValueError("Segwit Address Length Error[{address}]")
    else:
        raise ValueError("Address Format Error[{address}]")


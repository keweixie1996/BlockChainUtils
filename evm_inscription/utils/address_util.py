# -*- coding: utf-8 -*-

from eth_account import Account


def eth_account_from_mnemonic(mnemonic):
    Account.enable_unaudited_hdwallet_features()
    account = Account.from_mnemonic(mnemonic)
    address = account.address
    private_key = account.key.hex()
    return {"address": address, "privkey": private_key}

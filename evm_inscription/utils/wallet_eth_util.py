# -*- coding: utf-8 -*-

import asyncio
import logging
import json
import inspect
import os
import random
import requests
import time
import sys
import yaml

from asyncio import to_thread
from typing import Union, Optional
from pathlib import Path
from decimal import *

from web3 import Web3
from web3.types import HexBytes
from web3.datastructures import AttributeDict

from .retry import retry


logger = logging.getLogger(__name__)


EVM_PATH = Path(Path(__file__).parents[1].resolve(), "evm.yaml")
EVM = yaml.safe_load(open(EVM_PATH))


class AsyncWalletETHEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            return str(obj)
        elif isinstance(obj, HexBytes):
            return Web3.to_hex(obj)
        elif isinstance(obj, AttributeDict):
            return dict(obj)
        else:
            return super(AsyncWalletETHEncoder, self).default(obj)



class AsyncWalletETHBasic(object):

    def __init__(self, chain, wallet_address, wallet_privkey, mainnet=True):

        chain = chain.lower()
        self.network = "mainnet" if mainnet else "testnet"
        assert chain in EVM, f"BlockChain Not Support[{chain}]"

        self.chain = chain
        self.evm = EVM[self.chain][self.network]
        self.endpoint = self.evm["endpoint_public"]
        self.chain_id = self.evm["chain_id"]
        self.scan = self.evm["scan"]

        # web3 客户端
        self.web3 = Web3(Web3.HTTPProvider(self.endpoint))
        self.nonce_lock = asyncio.Lock()

        # 钱包账户信息
        self.wallet_address = self.web3.to_checksum_address(wallet_address)
        self.wallet_privkey = wallet_privkey


    def _get_gasprice(self):
        return self.web3.eth.gas_price


    async def get_gasprice(self, upper: float = 1.0):
        gasprice = await to_thread(self._get_gasprice)
        gasprice = int(gasprice * upper)
        return gasprice


    def token_wei2eth(self, number: int, decimals: int) -> Decimal:

        if number == 0:
            return Decimal(0)

        with localcontext() as ctx:
            ctx.prec = 999
            d_number = Decimal(value=number, context=ctx)
            result_value = d_number / (10 ** decimals)

        return result_value


    def token_eth2wei(
            self, number: Union[float, int, str, Decimal],
            decimals: Union[int, Decimal]) -> int:

        if isinstance(number, int) or isinstance(number, str):
            d_number = Decimal(value=number)
        elif isinstance(number, float):
            d_number = Decimal(value=str(number))
        elif isinstance(number, Decimal):
            d_number = number
        else:
            raise TypeError("Unsupported type.  "
                            "Must be one of integer, float, or string")

        s_number = str(number)
        decimals = Decimal(decimals)

        if d_number == Decimal(0):
            return 0

        if d_number < 1 and "." in s_number:
            with localcontext() as ctx:
                multiplier = len(s_number) - s_number.index(".") - 1
                ctx.prec = multiplier
                d_number = Decimal(value=number, context=ctx) * 10 ** multiplier
                d_number /= 10 ** multiplier

        with localcontext() as ctx:
            ctx.prec = 999
            result_value = Decimal(value=d_number, context=ctx) * (10**decimals)

        return int(result_value)


    def get_scan_address(self, address):
        return f"{self.scan}/address/{address}"


    def get_scan_transaction(self, txid):
        return f"{self.scan}/tx/{txid}"


    async def get_balance(self, address, wei=False):

        address = self.web3.to_checksum_address(address)
        balance = await to_thread(self.web3.eth.get_balance, address)
        if wei:
            return balance
        else:
            return self.web3.from_wei(balance, "ether")


    async def get_token_balance(self, address, wei=False):

        address = self.web3.to_checksum_address(address)
        balance = await to_thread(self.contract.functions.balanceOf(address).call)
        if wei:
            return balance
        else:
            return self.token_wei2eth(balance, self.contract_decimals)


    @retry(tries=5, delay=1)
    async def get_nonce(self, address):
        address = self.web3.to_checksum_address(address)
        async with self.nonce_lock:
            nonce = await to_thread(self.web3.eth.get_transaction_count, address)
            return nonce


    def get_wallet_scan_address(self):
        return self.get_scan_address(self.wallet_address)


    async def get_wallet_balance(self, wei=False):

        return await self.get_balance(self.wallet_address, wei=wei)


    async def get_wallet_token_balance(self, wei=False):

        return await self.get_token_balance(self.wallet_address, wei=wei)


    async def get_wallet_nonce(self):

        return await self.get_nonce(self.wallet_address)


    @retry(tries=5, delay=5)
    async def get_transaction_receipt(self, tx_hash, timeout=60):
        try:
            tx = await to_thread(
                self.web3.eth.wait_for_transaction_receipt,
                tx_hash, timeout=timeout)
            tx_detail = json.loads(json.dumps(tx, cls=AsyncWalletETHEncoder))
            tx_detail.pop("logsBloom")
            return tx_detail
        except Exception as e:
            info = {"error": str(e)}
            assert False, (f"GetTransactionReceipt:Error({json.dumps(info)})")


    @retry(tries=3, delay=0.1)
    async def transaction_ether(self, to_address, amount, nonce, data="", wait=False, gas_upper=1.1, need_from=False):

        to_address = self.web3.to_checksum_address(to_address)
        transaction = {
            "to_address": to_address,
            "amount_ether": amount,
            "transaction_from": "ether",
        }

        # transfer详情
        gasprice = await self.get_gasprice(upper=gas_upper)
        if self.chain == "cfx":
            gasprice = max(gasprice, 100000000000)
        if self.chain == "bsc":
            gasprice = max(gasprice, 3000000000)
        logging.info(f"Current GasPrice[{gasprice}]")
        tx = {
            "nonce": nonce,
            "to": to_address,
            "gasPrice": gasprice,
            "value": self.web3.to_wei(amount, "ether"),
            "chainId": int(self.chain_id),
        }
        if data:
            tx["data"] = data
        if need_from:
            tx["from"] = self.wallet_address
        # gas预估
        tx["gas"] = await to_thread(self.web3.eth.estimate_gas, tx)
        transaction["raw_transaction"] = tx
        transaction["ether:estimate_fee-wei"] = int(tx["gasPrice"] * tx["gas"])
        transaction["ether:balance-wei"] = await self.get_wallet_balance(wei=True)
        transaction["ether:value-wei"] = tx["value"]

        # 对交易进行签名
        sign_tx = await to_thread(
            self.web3.eth.account.sign_transaction,
            tx,
            self.wallet_privkey,
        )

        # 发送交易到区块链网络
        response = await to_thread(
            self.web3.eth.send_raw_transaction,
            sign_tx.rawTransaction)
        transaction_hash = self.web3.to_hex(response)
        if wait:
            res = await to_thread(
                self.get_transaction_receipt,
                transaction_hash,
            )
        transaction["transaction_hash"] = transaction_hash
        transaction["transaction_detail"] = self.get_scan_transaction(
            transaction["transaction_hash"],
        )

        return transaction





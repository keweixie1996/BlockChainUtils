# -*- coding: utf-8 -*-

import asyncio
import sys
import json
from typing import Union

from .retry import retry
from .async_requests_util import AsyncRequestClient



class MempoolAPIClient(AsyncRequestClient):


    def __init__(self, testnet=False):
        if testnet:
            self.endpoint = "https://mempool.space/testnet"
        else:
            self.endpoint = "https://mempool.space"
        super(MempoolAPIClient, self).__init__()


    #@retry(tries=3, delay=1)
    async def make_request(
        self, method: str, api: str,
        payload: Union[None, dict] = None,
        headers: dict = {},
        proxy: Union[None, str] = None,
        timeout: int = 180,
        data: Union[None, str] = None,
    ) -> Union[list, dict, str]:
        return await super().make_request(
            self.endpoint, method, api,
            payload=payload,
            headers=headers,
            proxy=proxy,
            timeout=timeout,
            data=data,
        )


    async def get_tip_hash(self) -> str:
        api = "/api/blocks/tip/hash"
        tip_hash = await self.make_request("GET", api)
        assert len(tip_hash) == 64, f"TipHash Get Failed[{tip_hash}]"
        return tip_hash


    async def get_block_detail(self, block_hash: str) -> dict:
        api = f"/api/block/{block_hash}"
        detail = await self.make_request("GET", api)
        assert isinstance(detail, dict) and "id" in detail, (
                f"BlockDetail Get Failed[{block_hash}]")
        return detail


    async def get_fees_recommended(self) -> dict:
        api = "/api/v1/fees/recommended"
        fees = await self.make_request("GET", api)
        assert isinstance(fees, dict) and "fastestFee" in fees, (
                f"FeesReco Get Failed[{fees}]")
        return fees


    async def get_block_txs(
        self,
        block_hash: str,
        start_idx: int = 0,
    ) -> list:
        assert start_idx % 25 == 0, (
                "StartIndex Must Be Multipication Of 25")
        api = f"/api/block/{block_hash}/txs/{start_idx}"
        txs = await self.make_request("GET", api)
        assert isinstance(txs, list), f"BlockTXs Get Failed[{block_hash}]"
        return txs


    async def tx_broadcast(
        self,
        txhex: str,
    ) -> str:
        api = f"/api/tx"
        try:
            txid = await self.make_request("POST", api, data=txhex)
        except Exception as e:
            assert False, f"Tx Broadcast Failed[{e}]"
        return txid


    async def get_address_utxos(
        self,
        address: str,
    ) -> list:
        api = f"/api/address/{address}/utxo"
        try:
            utxos = await self.make_request("GET", api)
        except Exception as e:
            assert False, f"UTXO Get Failed[{address}]"
        return utxos



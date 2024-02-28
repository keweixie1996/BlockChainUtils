# -*- coding: utf-8 -*-

import asyncio
import sys

sys.path.append("..")

from bcutils.btc.ordi_inscription import (
    ordi_mint,
    brc20_mint,
)



async def main():

    testnet = True

    # example: ordi mint
    """
    ordi_str_list = [
        "645169.bitnats",
        "645168.bitnats",
        "645180.bitnats",
        "645181.bitnats",
    ]
    txs = await ordi_mint(ordi_str_list, gas=2, testnet=testnet)
    #"""


    # example: brc20 mint
    """
    txs = await brc20_mint("eorb", "10", 2, gas=2, testnet=testnet)
    #"""


if __name__ == "__main__":
    asyncio.run(main())

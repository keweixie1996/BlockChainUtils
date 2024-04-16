# -*- coding: utf-8 -*-

import asyncio
import sys

sys.path.append("..")

from bcutils.btc.ordinals import (
    setup,
    ordi_mint,
    brc20_mint,
)



async def main():

    """
    1. 修改testnet为False
    2. mnemonic: 用于生成在mint过程中需要commit address和reveal address
        * 空: 会随机生成，请保存好运行过程中黄色的日志，防止运行报错时召回资产
        * 你自己地址的助记词: 保存好黄色日志中Path数据
    3. receive_address: 铭文接收地址
    """

    testnet = True
    mnemonic = ""
    receive_address = ""
    setup(testnet, mnemonic=mnemonic)

    # example: ordi mint
    """
    ordi_str_list = [
        "0.keweixie",
        "1.keweixie",
    ]
    txs = await ordi_mint(receive_address, ordi_str_list, gas=12)
    #"""


    # example: brc20 mint
    """
    txs = await brc20_mint(receive_address, "kewx", "10", 2, gas=12)
    #"""


if __name__ == "__main__":
    asyncio.run(main())

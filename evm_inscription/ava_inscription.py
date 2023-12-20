# -*- coding: utf-8 -*-

import asyncio
import sys
import json


from utils.inscription import ava_bulkmint_dataraw
from utils.common_util import init_logging
from utils.address_util import eth_account_from_mnemonic


async def main():

    init_logging()

    address = "Your Address"                    # like 0x16163b6eD32AB3b3E50B52cC7E6C8e87cFeB355d

    if True:
        # 如果只有助记词，替换掉下边助记词
        mnemonic = "word return address mint ttt http ttt column erase hello advance alcohol"
        private = eth_account_from_mnemonic(mnemonic)["private"]
    else:
        # 如果有私钥，请把19行True改成False
        private = "Your Private Key"            # like 0xe0ad1ee89a959a159aeefb95c27422d91e6c09a8dba44689b2a623d9241d1697

    to_address = "Inscription Receipt Address"  # like 0x16163b6eD32A93b3E50B51cC7E6C8e97cFeB355d
    dataraw = 'data:,{"p":"asc-20","op":"mint","tick":"dino","amt":"100000000"}'
    mint_count = 1
    await ava_bulkmint_dataraw(
        address,
        private,
        to_address,
        dataraw,
        mint_count,
    )



if __name__ == "__main__":
    asyncio.run(main())

# -*- coding: utf-8 -*-

import asyncio
import sys
import json
import yaml
from pathlib import Path

sys.path.append("..")

from bcutils.evm.inscription import ava_bulkmint_dataraw
from bcutils.utils.common_util import init_logging
from bcutils.utils.address_util import eth_account_from_mnemonic


EVM_PATH = Path(Path(__file__).parents[0].resolve(), "evm.yaml")
EVM = yaml.safe_load(open(EVM_PATH))


async def main():

    init_logging()

    address = "Your Address"                    # like 0x16163b6eD32AB3b3E50B52cC7E6C8e87cFeB355d

    if True:
        mnemonic = "word return address mint ttt http ttt column erase hello advance alcohol"
        private = eth_account_from_mnemonic(mnemonic)["private"]
    else:
        private = "Your Private Key"            # like 0xe0ad1ee89a959a159aeefb95c27422d91e6c09a8dba44689b2a623d9241d1697

    to_address = "Inscription Receipt Address"  # like 0x16163b6eD32A93b3E50B51cC7E6C8e97cFeB355d
    dataraw = 'data:,{"p":"asc-20","op":"mint","tick":"dino","amt":"100000000"}'
    mint_count = 1
    await ava_bulkmint_dataraw(
        evm,
        address,
        private,
        to_address,
        dataraw,
        mint_count,
    )



if __name__ == "__main__":
    asyncio.run(main())

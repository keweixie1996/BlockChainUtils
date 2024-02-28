# -*- coding: utf-8 -*-

import time
import asyncio
import logging
from asyncio import to_thread

from ..utils.wallet_eth_util import AsyncWalletETHBasic, AsyncWalletETHEncoder


def str2hexstr(s):
    s_bytes = s.encode("utf-8")
    s_hex = s_bytes.hex()
    return s_hex



async def bulkmint(evm, chain, address, private, to_address, datahex, count, waiting=1, gas_upper=1.1):
    assert count > 0, f"Mint Count Error => [{count}]"
    wallet = AsyncWalletETHBasic(evm, chain, address, private, mainnet=True)
    nonce = await wallet.get_wallet_nonce()
    for idx in range(count):
        try:
            response = await wallet.transaction_ether(
                to_address,
                0,
                nonce,
                data = datahex,
                gas_upper = gas_upper,
            )
            nonce += 1
            logging.info(f"Mint => [{response}]")
        except Exception as e:
            logging.error(e)
            await asyncio.sleep(5)
            nonce = await wallet.get_wallet_nonce()
        await asyncio.sleep(waiting)


async def ierc_mint(evm, chain, address, private, tick, amt, nonce=-1, prefix="0x0000"):
    wallet = AsyncWalletETHBasic(evm, chain, address, private, mainnet=True)
    if nonce == -1:
        nonce = await wallet.get_wallet_nonce()
    gasprice = await wallet.get_gasprice(upper=1.1)
    to_address = "0x0000000000000000000000000000000000000000"
    dataraw = ('data:application/json,'
        f'{{"p":"ierc-20","op":"mint",'
        f'"tick":"{tick}","amt":"{amt}","nonce":"__nonce__"}}'
    )
    mint_nonce = int(time.time()) * 1000
    count = 0
    while True:
        dataraw_c = dataraw.replace("__nonce__", str(mint_nonce+count))
        datahex = str2hexstr(dataraw_c)
        sign_tx = await wallet.build_transaction_ether(
            to_address, 0, nonce, gasprice, 30000, datahex,
        )
        tx_hash = sign_tx["hash"].hex()
        if count % 1000 == 0:
            logging.info(f"Minting [{count}] => [{tx_hash}]")
        if tx_hash.startswith(prefix):
            logging.info(f"Success [{count}] => [{tx_hash}]")
            break
        else:
            count += 1
    logging.info(sign_tx)
    response = await to_thread(
        wallet.web3.eth.send_raw_transaction,
        sign_tx.rawTransaction,
    )
    return response


async def eth_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "eth", address, private, to_address, datahex, count)


async def pol_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "pol", address, private, to_address, datahex, count, gas_upper=1.05)


async def op_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "op", address, private, to_address, datahex, count)


async def arb_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "arb", address, private, to_address, datahex, count)


async def ava_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "ava", address, private, to_address, datahex, count)


async def linea_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "linea", address, private, to_address, datahex, count)


async def celo_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "celo", address, private, to_address, datahex, count)


async def ftm_bulkmint_dataraw(evm, address, private, to_address, dataraw, count, waiting=30):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "ftm", address, private, to_address, datahex, count, waiting=waiting, gas_upper=1.05)


async def bsc_bulkmint_dataraw(evm, address, private, to_address, dataraw, count):
    datahex = str2hexstr(dataraw)
    await bulkmint(evm, "bsc", address, private, to_address, datahex, count)



# -*- coding:utf-8 -*-

import asyncio
import logging
import sys
import json
import time
from operator import itemgetter
from loguru import logger
from mnemonic import Mnemonic

from bitcoinutils.setup import setup as btc_setup
from bitcoinutils.utils import (
    to_satoshis,
    ControlBlock,
    calculate_tweak,
    tweak_taproot_privkey,
    prepend_varint,
    b_to_i,
)
from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import (
    PrivateKey,
    P2pkhAddress,
    P2shAddress,
    P2wpkhAddress,
    P2wshAddress,
    P2trAddress,
)
from bitcoinutils.hdwallet import HDWallet
from bitcoinutils.schnorr import *

from ..utils.mempool_api_util import MempoolAPIClient
from ..utils.address_util import (
    btc_mnemonic_to_root_xprivkey,
    btc_address_detecter,
)
from ..utils.codec_util import str2hexstr, hexstr2str


ORDI_HEX = "6f7264"                                             # ordi
TYPE_HEX = "746578742f706c61696e"                               # text/plain
TXID_REPLACE = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
ORDI_SATS = 546

TESTNET = True
NETWORK = "testnet"
MNEMONIC = ""
ROOT_XPRIKEY = ""
COMMIT_PATH = "m/86'/1'/0'/0"
REVEAL_PATH = "m/86'/1'/0'/1"


def setup(testnet: bool, mnemonic=None):

    global TESTNET, NETWORK, MNEMONIC, ROOT_XPRIKEY, COMMIT_PATH, REVEAL_PATH

    # setup mnemonic
    if mnemonic:
        MNEMONIC = mnemonic
    else:
        MNEMONIC = Mnemonic("english").generate(strength=128)
    logger.info(f"Mnemnoic [{MNEMONIC}]")
    logger.warning(f"一定要保存好[{MNEMONIC}]")

    TESTNET = testnet
    if testnet:
        NETWORK = "testnet"
        COMMIT_PATH = "m/86'/1'/0'/0"
        REVEAL_PATH = "m/86'/1'/0'/1"
        ROOT_XPRIKEY = btc_mnemonic_to_root_xprivkey(MNEMONIC, testnet=True)
    else:
        NETWORK = "mainnet"
        ROOT_XPRIKEY = btc_mnemonic_to_root_xprivkey(MNEMONIC, testnet=False)
        COMMIT_PATH = "m/86'/0'/0'/0"
        REVEAL_PATH = "m/86'/0'/0'/1"
    logger.info(f"RootPrivateKey [{ROOT_XPRIKEY}]")


def brc20_text_builder(op, tick, amt):
    assert op in {"mint", "transfer"}, f"brc-20 op must in {mint, transfer}"
    assert len(tick) == 4, f"len of tick must equal to 4"
    info = {
        "p": "brc-20",
        "op": op,
        "tick": tick,
        "amt": str(amt),
    }
    return json.dumps(info, separators=(",", ":"))


def brc20_hex_mint(tick, amt):
    brc20_text = brc20_text_builder("mint", tick, amt)
    logger.info(f"brc20-mint-detail[{brc20_text}]")
    brc20_hex = str2hexstr(brc20_text)
    logger.info(f"brc20-mint-hex[{brc20_hex}]")
    return brc20_hex


def brc20_hex_transfer(tick, amt):
    brc20_text = brc20_text_builder("transfer", tick, amt)
    logger.info(f"brc20-transfer-detail[{brc20_text}]")
    brc20_hex = str2hexstr(brc20_text)
    logger.info(f"brc20-transfer-hex[{brc20_hex}]")
    return brc20_hex


def build_privkey(path, mnemonic="", xprivate_key=""):
    assert xprivate_key or mnemonic, "xprivate_key and mnemonic can't be empty at the same time"
    if not xprivate_key:
        xprivate_key = btc_mnemonic_to_root_xprivkey(mnemonic, TESTNET)
    hdw = HDWallet(xprivate_key=xprivate_key, path=path)
    return hdw.get_private_key()



def build_commit_privkey(index: int = -1):
    if index == -1:
        path = f"{COMMIT_PATH}/{int(time.time())}"
    else:
        path = f"{COMMIT_PATH}/{index}"
    logger.warning(f"Build Commit Privkey[{ROOT_XPRIKEY}][{path}]")
    return build_privkey(path, xprivate_key=ROOT_XPRIKEY)


def build_reveal_privkey(index: int = -1):
    if index < 0:
        path = f"{REVEAL_PATH}/{int(time.time())}"
    else:
        path = f"{REVEAL_PATH}/{index}"
    logger.warning(f"Build Reveal Privkey[{ROOT_XPRIKEY}][{path}]")
    return build_privkey(path, xprivate_key=ROOT_XPRIKEY)


def build_commit_tx(
    commit_privkey,
    commit_pubkey,
    txins,
    in_amounts,
    txouts,
):

    commit_address = commit_pubkey.get_taproot_address()
    utxos_script_pubkeys = [
        commit_address.to_script_pub_key(),
    ]

    tx = Transaction(txins, txouts, has_segwit=True)

    sig = commit_privkey.sign_taproot_input(tx, 0, utxos_script_pubkeys, in_amounts)
    tx.witnesses.append(TxWitnessInput([sig]))

    return tx



def control_block_hex_fix(control_block, internal_pubkey, script):

    control_block_hex = control_block.to_hex()
    p = internal_pubkey.to_x_only_hex()
    P = lift_x(int_from_bytes(bytes.fromhex(p)))

    script_hex = script.to_hex()
    script_part = bytes([0xC0]) + prepend_varint(bytes.fromhex(script_hex))
    k0 = tagged_hash("TapLeaf", script_part)

    t = tagged_hash("TapTweak", bytes.fromhex(p) + k0)
    tweak_int = b_to_i(t)
    Q = point_add(P, point_mul(G, tweak_int))
    print(y(Q))

    logger.info(f"ControlBlockHex Fix Before[{control_block_hex}]")
    control_block_version = int(control_block_hex[:2], base=16) | y(Q) % 2
    control_block_fix = f"{control_block_version:2x}{control_block_hex[2:]}"
    logger.info(f"ControlBlockHex Fix After[{control_block_fix}]")

    return control_block_fix


def build_reveal_tx(
    reveal_privkey,
    reveal_pubkey,
    script,
    txins,
    in_amounts,
    txouts,
):

    reveal_address = reveal_pubkey.get_taproot_address([[script]])

    utxos_script_pubkeys = [
        reveal_address.to_script_pub_key(),
    ]

    tx = Transaction(txins, txouts, has_segwit=True)

    sig = reveal_privkey.sign_taproot_input(
        tx,
        0,
        utxos_script_pubkeys,
        in_amounts,
        script_path=True,
        tapleaf_script=script,
        tweak=False,
    )

    control_block = ControlBlock(reveal_pubkey)
    control_block_hex = control_block_hex_fix(
        control_block,
        reveal_pubkey,
        script,
    )

    tx.witnesses.append(TxWitnessInput([
        sig,
        script.to_hex(),
        control_block_hex,
    ]))

    return tx


def get_receive_witness_program(address):
    address_class = btc_address_detecter(address)
    if address_class == "P2wshAddress":
        raise ValueError("P2wshAddress Not Support[{address}]")
    witness_program = eval(f"{address_class}(address='{address}')").to_script_pub_key()
    return witness_program


def build_script(interal_pubkey, ordi_hex):
    script = Script([
        interal_pubkey.to_x_only_hex(),
        "OP_CHECKSIG",
        "OP_0",
        "OP_IF",
        ORDI_HEX,
        "01",
        TYPE_HEX,
        "OP_0",
        ordi_hex,
        "OP_ENDIF",
    ])
    return script


def build_script_pointer_mode(interal_pubkey, ordi_hex_list):
    def i_to_h(i):
        if i < 0x100:
            return i.to_bytes(byteorder="little").hex()
        elif i < 0x10000:
            return i.to_bytes(2, byteorder="little").hex()
        else:
            return i.to_bytes(3, byteorder="little").hex()
    script_init = [
        interal_pubkey.to_x_only_hex(),
        "OP_CHECKSIG",
        "OP_0",
        "OP_IF",
        ORDI_HEX,
        "01",
        TYPE_HEX,
        "OP_0",
        ordi_hex_list[0],
        "OP_ENDIF",
    ]
    for idx, ordi_hex in enumerate(ordi_hex_list[1:]):
        pointer = ORDI_SATS * (idx + 1)
        script_init += [
            "OP_0",
            "OP_IF",
            ORDI_HEX,
            "01",
            TYPE_HEX,
            "02",
            i_to_h(pointer),
            "OP_0",
            ordi_hex,
            "OP_ENDIF",
        ]
    return Script(script_init)


async def get_address_utxo(address, sats, mode="ge"):

    assert mode in {"ge", "eq"}, "Mode Must in {ge, eq}"

    client = MempoolAPIClient(testnet=TESTNET)
    btc = f"0.{sats:0>8d}"

    for t in range(60):
        logger.info(f"Look For Address[{address}]UTXO[{sats}]BTC[{btc}]")
        utxos = await client.get_address_utxos(address)
        if mode == "eq":
            utxos = [
                utxo for utxo in utxos
                if utxo["value"] == sats
            ]
        else:
            utxos = [
                utxo for utxo in utxos
                if utxo["value"] >= sats
            ]
        if not utxos:
            target_utxo = {}
        else:
            target_utxo = min(utxos, key=itemgetter("value"))
        if target_utxo:
            logger.info(f"Fund Valid UTXO[{address}][{target_utxo}]")
            break
        await asyncio.sleep(10)
    return target_utxo


async def tx_broadcast(txhex):

    client = MempoolAPIClient(testnet=TESTNET)

    try:
        txid = await client.tx_broadcast(txhex)
        logger.info(f"Tx Broadcast Success[{txhex}][{txid}]")
    except Exception as e:
        logger.error(f"Tx Broadcast Faild[{txhex}][{e}]")
        txid = ""

    return txid


async def ordi_minter(receive_address, ordi_hex_list, gas):

    logger.info(
        f"ORDI Minter Start"
        f"[receive_address={receive_address}]"
        f"[ordi_hex_list={ordi_hex_list}]"
        f"[gas={gas}]"
    )

    commit_privkey = build_commit_privkey(1713267002)
    commit_pubkey = commit_privkey.get_public_key()
    commit_address = commit_pubkey.get_taproot_address()
    logger.info(f"Commit Address[{commit_address.to_string()}]")

    reveal_privkey = build_reveal_privkey(1713267002)
    reveal_pubkey = reveal_privkey.get_public_key()

    # 构建接受铭文地址的witness program
    #receive_witness_program = P2trAddress(address=receive_address).to_script_pub_key()
    if TESTNET:
        receive_witness_program = P2trAddress(
            address=receive_address,
        ).to_script_pub_key()
    else:
        receive_witness_program = get_receive_witness_program(
            receive_address,
        )
    logger.info(f"Receive WitnessProgram[{receive_witness_program}]")

    reveal_total_sats = 0
    reveal_txouts_list = []
    for ordi_hex in ordi_hex_list:
        script = build_script(reveal_pubkey, ordi_hex)
        logger.info(f"Script[{script}]")
        reveal_address = reveal_pubkey.get_taproot_address([[script]])
        logger.info(f"Reveal Address[{reveal_address.to_string()}]")

        pre_reveal_tx = build_reveal_tx(
            reveal_privkey,
            reveal_pubkey,
            script,
            txins = [TxInput(TXID_REPLACE, 0)],
            in_amounts = [1000],
            txouts = [
                TxOutput(ORDI_SATS, receive_witness_program),
            ],
        )
        reveal_vsize = pre_reveal_tx.get_vsize()
        logger.info(f"Pre Reveal VSize[{reveal_vsize}][{script}]")
        reveal_fee_sats = round(reveal_vsize * gas)
        reveal_sats = reveal_fee_sats + ORDI_SATS
        reveal_txouts_list.append([reveal_sats, reveal_address, script])
        logger.info(f"Pre Reveal Sats[{reveal_sats}][{script}]")
        reveal_total_sats += reveal_sats
    logger.info(f"Pre Reveal Total Satoshi[{reveal_total_sats}]")

    pre_commit_tx = build_commit_tx(
        commit_privkey,
        commit_pubkey,
        txins = [TxInput(TXID_REPLACE, 0)],
        in_amounts = [1000],
        txouts = [
            TxOutput(ORDI_SATS, reveal_address.to_script_pub_key())
            for reveal_sats, reveal_address, rscript in reveal_txouts_list
        ],
    )

    commit_total_vsize = pre_commit_tx.get_vsize()
    logger.info(f"Pre Commit Total VSize[{commit_total_vsize}]")
    commit_fee_total_sats = round(commit_total_vsize * gas)
    commit_total_sats = commit_fee_total_sats + reveal_total_sats
    logger.info(f"Pre Commit Total Satoshi[{commit_total_sats}]")

    commit_utxo = await get_address_utxo(
        commit_address.to_string(),
        commit_total_sats,
        mode = "ge",
    )
    if not commit_utxo:
        logger.error(f"Can't Find Valid UTXO")
        return
    logger.info(f"UTXO Funded[{commit_utxo}]")

    change_sats = commit_utxo["value"] - commit_total_sats
    if change_sats > 0:
        logger.info(f"Change Not Zeor, Need Recalculate Commit Tx[{change_sats}]")
        txouts = [
            TxOutput(reveal_sats, reveal_address.to_script_pub_key())
            for reveal_sats, reveal_address, rscript in reveal_txouts_list
        ] + [
            TxOutput(change_sats, commit_address.to_script_pub_key()),
        ]
        fix_commit_tx = build_commit_tx(
            commit_privkey,
            commit_pubkey,
            txins = [TxInput(commit_utxo["txid"], commit_utxo["vout"])],
            in_amounts = [commit_utxo["value"]],
            txouts = [
                TxOutput(reveal_sats, reveal_address.to_script_pub_key())
                for reveal_sats, reveal_address, rscript in reveal_txouts_list
            ] + [
                TxOutput(change_sats, commit_address.to_script_pub_key()),
            ],
        )
        commit_total_vsize = fix_commit_tx.get_vsize()
        logger.info(f"Final Commit Total VSize[{commit_total_vsize}]")
        commit_fee_total_sats = round(commit_total_vsize * gas)
        commit_total_sats = commit_fee_total_sats + reveal_total_sats
        logger.info(f"Final Commit Total Satoshi[{commit_total_sats}]")
        change_sats = commit_utxo["value"] - commit_total_sats
        txouts = [
            TxOutput(reveal_sats, reveal_address.to_script_pub_key())
            for reveal_sats, reveal_address, rscript in reveal_txouts_list
        ] + [
            TxOutput(change_sats, commit_address.to_script_pub_key()),
        ]
    else:
        txouts = [
            TxOutput(reveal_sats, reveal_address.to_script_pub_key())
            for reveal_sats, reveal_address, rscript in reveal_txouts_list
        ]

    commit_tx = build_commit_tx(
        commit_privkey,
        commit_pubkey,
        txins = [TxInput(commit_utxo["txid"], commit_utxo["vout"])],
        in_amounts = [commit_utxo["value"]],
        txouts = txouts,
    )
    commit_txhex = commit_tx.serialize()
    logger.info(f"Final Commit Signed Raw TX[{commit_txhex}]")

    reveal_txhexs = []
    commit_txid = commit_tx.get_txid()
    for vout, (r_sats, r_address, r_script) in enumerate(reveal_txouts_list):
        txins = [TxInput(commit_txid, vout)]
        in_amounts = [r_sats]
        txouts = [TxOutput(ORDI_SATS, receive_witness_program)]
        reveal_tx = build_reveal_tx(
            reveal_privkey,
            reveal_pubkey,
            r_script,
            txins = txins,
            in_amounts = in_amounts,
            txouts = txouts,
        )
        reveal_txhex = reveal_tx.serialize()
        logger.info(f"Final Reveal Signed RawTx[index={vout}][{reveal_txhex}]")
        reveal_txhexs.append(reveal_txhex)

    txs = {}
    commit_txid = await tx_broadcast(commit_txhex)
    txs["commit_tx"] = {
        "txid": commit_txid,
        "txhex": commit_txhex,
    }
    txs["reveal_txs"] = []
    for tx in reveal_txhexs:
        txid = await tx_broadcast(tx)
        txs["reveal_txs"].append({
            "txid": txid,
            "txhex": tx,
        })

    return txs


async def ordi_minter_pointer_mode(receive_address, ordi_hex_list, gas, commit_privkey=None):

    logger.info(
        f"ORDI Minter Seperate-Output Point Mode Start"
        f"[receive_address={receive_address}]"
        f"[ordi_hex_list={ordi_hex_list}]"
        f"[gas={gas}]"
    )

    reveal_privkey = build_reveal_privkey()
    reveal_pubkey = reveal_privkey.get_public_key()


    # 构建接受铭文地址的witness program
    #receive_witness_program = P2trAddress(address=receive_address).to_script_pub_key()
    if TESTNET:
        receive_witness_program = P2trAddress(
            address=receive_address,
        ).to_script_pub_key()
    else:
        receive_witness_program = get_receive_witness_program(
            receive_address,
        )
    logger.info(f"Receive WitnessProgram[{receive_witness_program}]")

    script = build_script_pointer_mode(reveal_pubkey, ordi_hex_list)
    reveal_address = reveal_pubkey.get_taproot_address([[script]])
    logger.info(f"Reveal Address[{reveal_address.to_string()}]")

    reveal_txouts = [
        TxOutput(ORDI_SATS, receive_witness_program)
    ]
    pre_reveal_tx = build_reveal_tx(
        reveal_privkey,
        reveal_pubkey,
        script,
        txins = [TxInput(TXID_REPLACE, 0)],
        in_amounts = [1000],
        txouts = [
            TxOutput(ORDI_SATS, receive_witness_program),
        ] * len(ordi_hex_list),
    )
    reveal_vsize = pre_reveal_tx.get_vsize()
    logger.info(f"Pre Reveal VSize[{reveal_vsize}][{script}]")
    reveal_fee_sats = round(reveal_vsize * gas)
    reveal_sats = reveal_fee_sats + ORDI_SATS * len(ordi_hex_list)
    logger.info(f"Reveal Total Satoshi[{reveal_sats}]")

    reveal_utxo = await get_address_utxo(
        reveal_address.to_string(),
        reveal_sats,
        mode = "eq",
    )
    if not reveal_utxo:
        logger.error(f"Can't Find Valid UTXO")
        return
    logger.info(f"UTXO Funded[{reveal_utxo}]")

    reveal_tx = build_reveal_tx(
        reveal_privkey,
        reveal_pubkey,
        script,
        txins = [TxInput(reveal_utxo["txid"], 0)],
        in_amounts = [reveal_sats],
        txouts = [
            TxOutput(ORDI_SATS, receive_witness_program)
        ] * len(ordi_hex_list),
    )
    reveal_txhex = reveal_tx.serialize()
    logger.info(f"Final Reveal Signed RawTx[{reveal_txhex}]")

    reveal_txid = await tx_broadcast(reveal_txhex)
    txs = {
        "txid": reveal_txid,
        "txhex": reveal_txhex,
    }
    return txs


async def ordi_mint(receive_address, ordi_str_list, gas=10):

    btc_setup(NETWORK)

    ordi_hex_list = [str2hexstr(ordi) for ordi in ordi_str_list]
    txs = await ordi_minter_pointer_mode(receive_address, ordi_hex_list, gas)
    logger.info(json.dumps(txs, indent=1))
    return txs


async def brc20_mint(receive_address, brc20, amount, repeat, gas=1):

    btc_setup(NETWORK)

    brc20_hex = brc20_hex_mint(brc20, str(amount))
    txs = await ordi_minter(receive_address, [brc20_hex]*repeat, gas)
    logger.info(json.dumps(txs, indent=1))
    return txs


async def main():

    await asyncio.sleep(10000)



if __name__ == "__main__":
    asyncio.run(main())


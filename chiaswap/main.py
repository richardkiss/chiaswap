#!/usr/bin/env python3

import hashlib
import json
import os
import secrets
import urllib.request

from decimal import Decimal
from typing import Tuple

import blspy

from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import Program
from chia.types.spend_bundle import SpendBundle
from chia.types.coin_spend import CoinSpend
from chia.util.bech32m import decode_puzzle_hash, encode_puzzle_hash
from chia.wallet.puzzles.p2_conditions import puzzle_for_conditions
from chia.wallet.puzzles.p2_delegated_puzzle_or_hidden_puzzle import (
    calculate_synthetic_offset,
    puzzle_for_public_key_and_hidden_puzzle_hash,
    solution_for_conditions,
    solution_for_hidden_puzzle,
)
from chia.wallet.puzzles.load_clvm import load_clvm

from .bech32m import bech32_decode, convertbits


GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

P2_DELAYED_OR_PREIMAGE = load_clvm("p2_delayed_or_preimage.cl", __name__)

ADDITIONAL_DATA = bytes.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)

OWNERSHIP_MESSAGE = b"I own this key"


def lookup_xch_prices():
    print("prices from cryptocompare.com")
    prices = json.load(
        urllib.request.urlopen(
            "https://min-api.cryptocompare.com/data/price?fsym=XCH&tsyms=USD,BTC"
        ),
        parse_float=Decimal,
    )
    return prices


def fromhex(s):
    if s.lower().startswith("0x"):
        s = s[2:]
    return bytes.fromhex(s)


# ### ui


def ui_get_logfile():
    path = "xchlog.txt"
    if not os.path.exists(path):
        with open(path, "a") as f:
            secret_key = secrets.randbits(256)
            f.write(f"{secret_key}\n")

    file_lines = open(path).readlines()
    secret_key = int(file_lines[0])
    file_lines = file_lines[1:]

    def logfile(msg):
        nonlocal file_lines
        while len(file_lines) > 0:
            line, file_lines = file_lines[0], file_lines[1:]
            if line.startswith("#"):
                continue
            import time

            time.sleep(0.125)
            print("%s%s" % (msg, line))
            return line[:-1]
        r = input(f"{msg}")
        with open(path, "a") as f:
            f.write(f"{r}\n")
        return r

    return logfile, secret_key


def ui_choose(input):
    while 1:
        print("1. Have XCH, want BTC")
        print("2. Have BTC, want XCH")
        choice = input("> ")
        if choice in ("1", "2"):
            return int(choice)


def ui_get_amounts(input):
    prices = lookup_xch_prices()
    BTC_PER_XCH = prices["BTC"]
    USD_PER_XCH = prices["USD"]
    USD_PER_BTC = USD_PER_XCH / BTC_PER_XCH

    print("1 XCH = %0.6f BTC" % BTC_PER_XCH)
    print("1 BTC = %0.6f XCH" % (1 / BTC_PER_XCH))
    print(
        "USD estimates are based on $%0.2f/BTC and $%0.2f/XCH"
        % (USD_PER_BTC, USD_PER_XCH)
    )
    print()
    xch_amount = Decimal(input("How much XCH is being traded? > "))
    btc_amount = xch_amount * BTC_PER_XCH
    print(
        "%s XCH worth about %0.6f btc (USD$%0.2f)"
        % (xch_amount, btc_amount, USD_PER_XCH * xch_amount)
    )
    print()
    return btc_amount, xch_amount


def ui_get_puzzle_hash(input, msg):
    while 1:
        address = input(msg)
        if not address.startswith("xch"):
            continue
        puzzle_hash = decode_puzzle_hash(address)
        return puzzle_hash


def ui_get_lightning_payment_request(input):
    while 1:
        r = input("> ")
        if validate_lpr(r):
            return r
        print("invalid")


def ui_get_parent_coin_id(input):
    while 1:
        r = input("parent id> ")
        try:
            b = fromhex(r)
            if len(b) == 32:
                return b
        except Exception:
            pass
        print("parent coin id is a 64 character hex string")


def ui_get_pubkey(input):
    while 1:
        r = input("enter counter-party pubkey> ")
        try:
            b = fromhex(r)
            g1 = blspy.G1Element.from_bytes(b)
            return g1
        except Exception:
            pass
        print("pubkey is a 96 character hex string")


def ui_get_private_key(input, public_key):
    while 1:
        r = input("enter counter-party private key\n> ")
        try:
            p = int(r, 16) % GROUP_ORDER
            private_key = private_key_for_secret(p)
            if private_key.get_g1() == public_key:
                return p
            print("this private key doesn't match the public key")
            continue
        except Exception:
            pass
        print("private key is a 64 character hex string")


def ui_get_pubkey_with_sig(input):
    while 1:
        r = input("> ")
        r = r.strip()
        try:
            puzzle_hash_hex, sig_hex = r.split("_")
            b1 = fromhex(puzzle_hash_hex)
            g1 = blspy.G1Element.from_bytes(b1)
            b2 = fromhex(sig_hex)
            g2 = blspy.G2Element.from_bytes(b2)
            r = blspy.AugSchemeMPL.verify(g1, OWNERSHIP_MESSAGE, g2)
            if not r:
                print("bad signature!")
                continue
            return g1
        except Exception:
            pass
        print(
            'wrong format: expecting 64 hex digits followed by a "_" character, then 96 hex digits'
        )


def ui_get_sweep_preimage(input, sweep_receipt_hash):
    while 1:
        r = input("> ").strip().lower()
        try:
            b = fromhex(r)
            if hashlib.sha256(b).digest() == sweep_receipt_hash:
                return b
            print("the hash of that doesn't match")
        except Exception:
            pass
        print("invalid, try again")


# ### end ui


def clawback_or_sweep_solution(
    total_pubkey,
    clawback_delay_seconds,
    clawback_public_key,
    sweep_receipt_hash,
    sweep_public_key,
    conditions,
    sweep_preimage,
):
    hidden_puzzle = generate_hidden_puzzle(
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
    )

    delegated_solution = solution_for_conditions(conditions)

    p2_delayed_or_preimage_solution = Program.to([sweep_preimage, delegated_solution])

    solution = solution_for_hidden_puzzle(
        total_pubkey, hidden_puzzle, p2_delayed_or_preimage_solution
    )
    return solution


def parse_lpr(lpr):
    prefix, data, spec = bech32_decode(lpr, max_length=2048)

    OVERRIDE_SIZES = {1: 256, 16: 256}

    d = {}
    tagged = data[7:]
    while len(tagged) * 5 > 520:
        type = tagged[0]
        size = convertbits(tagged[1:3], 5, 10)[0]
        data_blob = tagged[3 : 3 + size]
        bit_size = OVERRIDE_SIZES.get(type, 5 * size)
        if size > 0:
            data = convertbits(data_blob, 5, bit_size)[0]
        else:
            data = None
        tagged = tagged[3 + size :]
        if size > 10:
            data = data.to_bytes((bit_size + 7) >> 3, byteorder="big")
        d[type] = data

    signature = convertbits(tagged, 5, 520)[0]
    d["signature"] = signature
    return d


def validate_lpr(lpr):
    r = hash_for_lpr(lpr)
    return len(r) == 32


def hash_for_lpr(lpr):
    d = parse_lpr(lpr)
    return d[1]


def private_key_for_secret(s):
    s %= GROUP_ORDER
    return blspy.PrivateKey.from_bytes(s.to_bytes(32, byteorder="big"))


def pubkey_for_secret(s):
    return private_key_for_secret(s).get_g1()


def signed_pubkey_for_secret(s):
    private_key = private_key_for_secret(s)
    public_key = private_key.get_g1()
    sig = blspy.AugSchemeMPL.sign(private_key, OWNERSHIP_MESSAGE, public_key)
    return public_key, f"{bytes(public_key).hex()}_{bytes(sig).hex()}"


def generate_hidden_puzzle(
    clawback_delay_seconds,
    clawback_public_key,
    sweep_receipt_hash,
    sweep_public_key,
) -> Program:
    hidden_puzzle = P2_DELAYED_OR_PREIMAGE.curry(
        (clawback_delay_seconds, clawback_public_key),
        (sweep_receipt_hash, sweep_public_key),
    )
    return hidden_puzzle


def solve_p2_delayed_or_preimage(
    delegated_puzzle: Program, delegated_solution: Program, sweep_preimage: bytes = b""
) -> Program:
    return Program.to([sweep_preimage, [delegated_puzzle, delegated_solution]])


def generate_holding_address(
    total_pubkey,
    clawback_delay_seconds,
    clawback_public_key,
    sweep_receipt_hash,
    sweep_public_key,
) -> Tuple[Program, int]:

    hidden_puzzle = generate_hidden_puzzle(
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
    )
    hidden_puzzle_hash = hidden_puzzle.get_tree_hash()
    puzzle = puzzle_for_public_key_and_hidden_puzzle_hash(
        total_pubkey, hidden_puzzle_hash
    )
    synthetic_offset = calculate_synthetic_offset(total_pubkey, hidden_puzzle_hash)
    return puzzle, synthetic_offset


def generate_spendbundle(
    parent_coin_id,
    xch_amount_mojos,
    total_pubkey,
    clawback_delay_seconds,
    clawback_public_key,
    sweep_receipt_hash,
    sweep_public_key,
    conditions,
    sweep_preimage=0,
) -> SpendBundle:

    puzzle_reveal, synthetic_offset = generate_holding_address(
        total_pubkey,
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
    )
    puzzle_hash = puzzle_reveal.get_tree_hash()

    coin = Coin(parent_coin_id, puzzle_hash, xch_amount_mojos)
    solution = clawback_or_sweep_solution(
        total_pubkey,
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
        conditions,
        sweep_preimage,
    )
    coin_spend = CoinSpend(coin, puzzle_reveal, solution)
    spend_bundle = SpendBundle([coin_spend], blspy.G2Element())
    return spend_bundle


def sign_spend_bundle(coin_spend, conditions, secret, additional_data):
    message = (
        puzzle_for_conditions(conditions).get_tree_hash()
        + coin_spend.coin.name()
        + additional_data
    )

    total_sig = blspy.AugSchemeMPL.sign(private_key_for_secret(secret), message)
    return SpendBundle([coin_spend], total_sig)


def have_xch_want_btc(logfile, secret_key, btc_amount, xch_amount_mojos):
    s = secret_key
    clawback_public_key, my_pubkey_string = signed_pubkey_for_secret(s)
    print("Send the long line below to your counter-party. It contains your")
    print("signed public key.")
    print(my_pubkey_string)
    print()

    print("enter your counter-party's public key as pasted by them")
    sweep_public_key = ui_get_pubkey_with_sig(logfile)
    print()

    total_pubkey = sweep_public_key + clawback_public_key

    print(
        f"In your lightning wallet, create a lightning payment request for {btc_amount} BTC"
    )
    print("The timeout must be at least ten minutes.")
    print("Copy and paste the lightning payment request here.")
    print()
    lpr = ui_get_lightning_payment_request(logfile)
    d = parse_lpr(lpr)
    sweep_receipt_hash = d[1]

    # TODO: fix the next line
    clawback_delay_seconds = 86400

    puzzle_reveal, synthetic_offset = generate_holding_address(
        total_pubkey,
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
    )
    puzzle_hash = puzzle_reveal.get_tree_hash()
    address = encode_puzzle_hash(puzzle_hash, "xch")
    xch_amount = Decimal(xch_amount_mojos) / Decimal(int(1e12))
    print()
    print(f"go into your XCH wallet and send {xch_amount} XCH to")
    print(f"{address}")
    print()
    print("Go to an explorer and look up the parent coin info/name (32 byte hex)")
    print(f"https://chia.tt/info/address/{address}")
    print(" => then click on `Coin Name`")
    # print(f"https://xchscan.com/address/{address} (not sure how to find it here)")
    # print(f"https://www.chiaexplorer.com/blockchain/address/{address} (not sure how to find it here)")
    print()
    print("Enter it below")
    parent_coin_id = ui_get_parent_coin_id(logfile)

    print()
    print("You need to enter a refund address where your XCH will be returns if")
    print("the swap fails. It can be an address from a wallet or an exchange.")
    print()

    clawback_puzzle_hash = ui_get_puzzle_hash(logfile, "enter XCH refund address > ")

    conditions = [[51, clawback_puzzle_hash, xch_amount_mojos]]

    spend_bundle = generate_spendbundle(
        parent_coin_id,
        xch_amount_mojos,
        total_pubkey,
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
        conditions,
    )

    spend_bundle = sign_spend_bundle(
        spend_bundle.coin_spends[0], conditions, s, ADDITIONAL_DATA
    )

    hours = clawback_delay_seconds // 3600
    spend_bundle_hex = bytes(spend_bundle).hex()
    print()
    print("Wait for the lightning invoice payment.")
    print()
    print("When you get it, you can immediately share the private key below with")
    print("your counter-party to allow them to cleanly claim the XCH funds.")
    print()

    print(f"private key: 0x{s:064x}")
    print()
    print("If it never happens, use the spendbundle below to claw it back")
    print(f"after {hours} hours.")
    print()
    print(f"clawback spend bundle: {spend_bundle_hex}")
    # spend_bundle.debug()
    return


def have_btc_want_xch(logfile, secret_key, btc_amount, xch_amount_mojos):
    s = secret_key + 1
    sweep_public_key, my_pubkey_string = signed_pubkey_for_secret(s)

    print("Send the long line below to your counter-party. It contains your")
    print("signed public key.")
    print(my_pubkey_string)
    print()

    print("enter your counter-party's public key as pasted by them")
    clawback_public_key = ui_get_pubkey_with_sig(logfile)
    print()

    total_pubkey = sweep_public_key + clawback_public_key

    print()
    print("Paste the lightning payment request from your counter-party here.")
    lpr = ui_get_lightning_payment_request(logfile)
    print()
    d = parse_lpr(lpr)
    sweep_receipt_hash = d[1]

    total_pubkey = sweep_public_key + clawback_public_key
    clawback_delay_seconds = 86400

    puzzle_reveal, synthetic_offset = generate_holding_address(
        total_pubkey,
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
    )
    puzzle_hash = puzzle_reveal.get_tree_hash()
    address = encode_puzzle_hash(puzzle_hash, "xch")
    xch_amount = Decimal(xch_amount_mojos) / Decimal(int(1e12))
    print(f"Your counter-party should be sending {xch_amount} XCH to the address")
    print(f"{address}")
    print()
    print("Go to an explorer and look up the parent coin info/name (32 byte hex)")
    print(f"https://chia.tt/info/address/{address}")
    print(" => then click on `Coin Name`")
    # print(f"https://xchscan.com/address/{address} (not sure how to find it here)")
    # print(
    #    f"https://www.chiaexplorer.com/blockchain/address/{address} (not sure how to find it here)"
    # )
    print()
    print("Enter it below")
    parent_coin_id = ui_get_parent_coin_id(logfile)
    print()
    print("Once your XCH has enough confirmations, pay the lightning invoice.")
    print()
    print("If you DO NOT want to complete this transaction, DO NOT pay the")
    print("lightning invoice. Instead, send the following private key to your")
    print("counterparty to allow them to cleanly reclaim the XCH funds.")
    print()

    print(f"private key: 0x{s:064x}")
    print()

    print("Enter the lightning invoice receipt preimage")
    sweep_preimage = ui_get_sweep_preimage(logfile, sweep_receipt_hash)

    print()
    print("Enter an address where your XCH will be delivered.")
    print("It can be an address from a wallet or an exchange.")
    print()
    sweep_puzzle_hash = ui_get_puzzle_hash(logfile, "XCH address > ")
    print()

    # TODO: fix these next two lines
    conditions = [[51, sweep_puzzle_hash, xch_amount_mojos]]

    coin = Coin(parent_coin_id, puzzle_hash, xch_amount_mojos)
    coin_spend = CoinSpend(coin, puzzle_reveal, solution_for_conditions(conditions))
    message = (
        puzzle_for_conditions(conditions).get_tree_hash()
        + coin.name()
        + ADDITIONAL_DATA
    )

    spend_bundle = generate_spendbundle(
        parent_coin_id,
        xch_amount_mojos,
        total_pubkey,
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
        conditions,
        sweep_preimage,
    )

    coin = Coin(parent_coin_id, puzzle_hash, xch_amount_mojos)
    message = (
        puzzle_for_conditions(conditions).get_tree_hash()
        + coin.name()
        + ADDITIONAL_DATA
    )

    total_sig = blspy.AugSchemeMPL.sign(private_key_for_secret(s), message)
    spend_bundle = SpendBundle(spend_bundle.coin_spends, total_sig)

    spend_bundle_hex = bytes(spend_bundle).hex()
    print(f"sweep spend bundle: {spend_bundle_hex}")
    # spend_bundle.debug()
    print()
    print("Your counterparty should share their (disposable) private key")
    print("with you now. If your counterparty disappears before sending it,")
    print("you can use the spend bundle above as a last resort.")
    print()

    remote_secret = ui_get_private_key(logfile, clawback_public_key)
    total_secret = remote_secret + s + synthetic_offset

    total_private_key = private_key_for_secret(total_secret)

    print()

    # build local signatures

    total_sig = blspy.AugSchemeMPL.sign(total_private_key, message)
    clean_spend_bundle = SpendBundle([coin_spend], total_sig)
    # clean_spend_bundle.debug()
    print(f"clean spend bundle: {bytes(clean_spend_bundle).hex()}")
    print()
    print("Use the spend bundle above because it's smaller and is")
    print("indistinguishable from standard spend, so will give")
    print("the participants (you) more privacy.")


def main():
    logfile, secret_key = ui_get_logfile()
    btc_amount, xch_amount = ui_get_amounts(logfile)
    xch_amount_mojos = int(xch_amount * Decimal(1e12))
    which_way = ui_choose(logfile)
    print()
    f = have_xch_want_btc if which_way == 1 else have_btc_want_xch
    f(logfile, secret_key, btc_amount, xch_amount_mojos)


if __name__ == "__main__":
    main()

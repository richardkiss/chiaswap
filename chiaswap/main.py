#!/usr/bin/env python3

import asyncio
import concurrent.futures
import datetime
import hashlib
import json
import time
import re
import os
import secrets
import time
import urllib.request
import urllib.error

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
from .pushtx import push_tx


GROUP_ORDER = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

P2_DELAYED_OR_PREIMAGE = load_clvm("p2_delayed_or_preimage.clsp", __name__)

ADDITIONAL_DATA = bytes.fromhex(
    "ccd5bb71183532bff220ba46c268991a3ff07eb358e8255a65c30a2dce0e5fbb"
)

OWNERSHIP_MESSAGE = b"I own this key"


def lookup_xch_prices():
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
    if len(s) & 1 == 1:
        s = f"0{s}"
    return bytes.fromhex(s)


def wait_for_payments_to_address(address, min_amount):
    root_url = "https://api2.spacescan.io"
    addr_url = f"{root_url}/1/xch/address/txns"
    while 1:
        print(f"checking for payments to {address}")
        resp = urllib.request.urlopen(f"{addr_url}/{address}", timeout=10)
        if resp.status == 200:
            coins = json.load(resp, parse_float=Decimal)["data"]["coins"][::-1]
            for coin in coins:
                amount = int(coin["amount"])
                if amount >= min_amount:
                    return [coin]
        time.sleep(5)


# ### ui


def ui_choose_path(possible_paths):
    if len(possible_paths) > 0:
        while 1:
            print(f" 0. NEW SWAP")
            for idx, pp in enumerate(possible_paths):
                print(f"{(idx+1):2}. {pp}")
            r = input("> ")
            try:
                v = int(r)
                if v == 0:
                    break
                return possible_paths[v - 1]
            except ValueError:
                pass
    name = input('(optional) short name for counterparty (example: "ed")> ')
    if len(name) > 0:
        name = f"-{name}"
    now = datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S")
    path = f"xchswap-log-{now}{name}.txt"
    return path


def ui_get_logfile():
    cre = re.compile(r"xchswap-log-(\d{4})-(\d{2})-(\d{2})-(\d{6})(\-.+)?.txt")
    possible_paths = [_ for _ in os.listdir(".") if cre.match(_)]
    possible_paths.sort()
    path = ui_choose_path(possible_paths)

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


def ui_get_amounts(input, prices):
    print("prices from cryptocompare.com")
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
    print("How much XCH fee (default: 0.00005 mojos)?")
    print("(You should agree your fee with your counterparty. The fee will be used for either clawback, clean, or sweep spend.)")
    fee_amount = Decimal(input("> ") or "0.00005")
    btc_amount = xch_amount * BTC_PER_XCH
    print(
        "%0.13f XCH worth about %0.8f btc (USD$%0.2f)"
        % (xch_amount, btc_amount, USD_PER_XCH * xch_amount)
    )
    print()
    return btc_amount, xch_amount, fee_amount


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


def ui_get_private_key(input, public_key):
    while 1:
        r = input("enter counterparty private key\n> ")
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


def ui_get_pubkey_with_sig(input, my_pubkey):
    while 1:
        r = input("> ")
        r = r.strip()
        try:
            puzzle_hash_hex, sig_hex = r.split("_")
            b1 = fromhex(puzzle_hash_hex)
            g1 = blspy.G1Element.from_bytes(b1)
            if g1 == my_pubkey:
                print()
                print("that's your public key, silly! Try again.")
                continue
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


def ui_get_sweep_preimage_or_private_key(
    input, sweep_receipt_hash, clawback_public_key
):
    while 1:
        r = input("> ").strip().lower()
        if r == "quit":
            return None, None, True
        try:
            p = int(r, 16) % GROUP_ORDER
            private_key = private_key_for_secret(p)
            if private_key.get_g1() == clawback_public_key:
                return None, p, False
            b = fromhex(r)
            if hashlib.sha256(b).digest() == sweep_receipt_hash:
                return b, None, False
        except Exception:
            pass
        print("this isn't the private key nor the pre-image")
        print("each is a 64 character hex string")


def ui_should_send_spend_bundle():
    r = input("send this spend bundle? (Y/N) > ")
    return r.lower().startswith("y")


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
    fee_amount_mojos,
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

    coin = Coin(parent_coin_id, puzzle_hash, xch_amount_mojos + fee_amount_mojos)
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


def have_xch_want_btc(logfile, secret_key, btc_amount, xch_amount_mojos, fee_amount_mojos):
    s = secret_key
    clawback_public_key, my_pubkey_string = signed_pubkey_for_secret(s)
    print("Send the long line below to your counterparty. It contains your")
    print("signed public key.")
    print(my_pubkey_string)
    print()

    print("enter your counterparty's public key as pasted by them")
    sweep_public_key = ui_get_pubkey_with_sig(logfile, clawback_public_key)

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
    fee_amount = Decimal(fee_amount_mojos) / Decimal(int(1e12))

    print(f"go into your XCH wallet and send {xch_amount + fee_amount} XCH to")
    print(f"{address}")
    print()

    print("You need to enter a refund address where your XCH will be returns if")
    print("the swap fails. It can be an address from a wallet or an exchange.")
    print()
    clawback_puzzle_hash = ui_get_puzzle_hash(logfile, "enter XCH refund address > ")

    coins = wait_for_payments_to_address(address, xch_amount_mojos + fee_amount_mojos)
    parent_coin_id = fromhex(coins[0]["coin_parent"])
    conditions = [[51, clawback_puzzle_hash, xch_amount_mojos]]

    spend_bundle = generate_spendbundle(
        parent_coin_id,
        xch_amount_mojos,
        fee_amount_mojos,
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
    print("your counterparty to allow them to cleanly claim the XCH funds.")
    print()

    print(f"private key: 0x{s:064x}")
    print()
    print("If it never happens, use the spendbundle below to claw it back")
    print(f"after {hours} hours.")
    print()
    print(f"clawback spend bundle: {spend_bundle_hex}")
    print()
    print(f"waiting {clawback_delay_seconds} s then pushing the clawback spend bundle")
    print(f"Leave this window open or control-c to exit.")
    print()
    print(
        f"Warning: if you answer before {clawback_delay_seconds} seconds have elapsed,"
    )
    print(
        "the spend bundle will be rejected. No harm done though, you'll just have to try later."
    )
    if ui_should_send_spend_bundle():
        try_to_push_tx(spend_bundle, clawback_puzzle_hash)


def try_to_push_tx(sb, dest_puzzle_hash):
    print()
    print(f"Check your wallet or an explorer to confirm.")
    address = encode_puzzle_hash(dest_puzzle_hash, "xch")
    print(f"https://www.spacescan.io/xch/address/{address}")
    print()
    r = asyncio.run(push_tx(sb))
    if r == 0:
        print("It seems to have worked.")
    else:
        print("*** The spend bundle may not have been accepted.")


def have_btc_want_xch(logfile, secret_key, btc_amount, xch_amount_mojos, fee_amount_mojos):
    s = secret_key + 1
    sweep_public_key, my_pubkey_string = signed_pubkey_for_secret(s)

    print("Send the long line below to your counterparty. It contains your")
    print("signed public key.")
    print(my_pubkey_string)
    print()

    print("enter your counterparty's public key as pasted by them")
    clawback_public_key = ui_get_pubkey_with_sig(logfile, sweep_public_key)

    total_pubkey = sweep_public_key + clawback_public_key

    print("Paste the lightning payment request from your counterparty here.")
    lpr = ui_get_lightning_payment_request(logfile)
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
    fee_amount = Decimal(fee_amount_mojos) / Decimal(int(1e12))

    print("Enter an address where your XCH will be delivered.")
    print("It can be an address from a wallet or an exchange.")
    print()
    sweep_puzzle_hash = ui_get_puzzle_hash(logfile, "XCH address > ")

    print(f"Your counterparty should be sending {xch_amount + fee_amount} XCH to the address")
    print(f"{address}")
    print()
    print("Go to an explorer and watch for payments")
    print()
    print(f"https://www.spacescan.io/xch/address/{address}")
    print()
    coins = wait_for_payments_to_address(address, xch_amount_mojos)
    parent_coin_id = fromhex(coins[0]["coin_parent"])

    print()
    print("Once your XCH has enough confirmations, pay the lightning invoice.")
    print()
    print("If you DO NOT want to complete this transaction, DO NOT pay the")
    print("lightning invoice. Instead, send the following private key to your")
    print("counterparty to allow them to cleanly reclaim the XCH funds.")
    print()

    print(f"private key: 0x{s:064x}")
    print()

    print("Once you've paid the lightning invoice, ask your counterparty to")
    print("share their private key. Meanwhile, look up your lightning invoice")
    print("receipt pre-image in case your counterparty doesn't respond.")
    print()

    # TODO: fix these next two lines
    conditions = [[51, sweep_puzzle_hash, xch_amount_mojos]]

    coin = Coin(parent_coin_id, puzzle_hash, xch_amount_mojos + fee_amount_mojos)
    coin_spend = CoinSpend(coin, puzzle_reveal, solution_for_conditions(conditions))
    message = (
        puzzle_for_conditions(conditions).get_tree_hash()
        + coin.name()
        + ADDITIONAL_DATA
    )

    while True:
        print(
            "Enter your counterparty private key OR the lightning invoice receipt pre-image or `quit`"
        )
        (
            sweep_preimage,
            remote_secret,
            should_quit,
        ) = ui_get_sweep_preimage_or_private_key(
            logfile, sweep_receipt_hash, clawback_public_key
        )

        if should_quit:
            break

        if sweep_preimage:
            sweep_spend_bundle = handle_sweep_preimage(
                s,
                puzzle_hash,
                parent_coin_id,
                xch_amount_mojos,
                fee_amount_mojos,
                total_pubkey,
                clawback_delay_seconds,
                clawback_public_key,
                sweep_receipt_hash,
                sweep_public_key,
                conditions,
                sweep_preimage,
            )
            print("You should wait for your counterparty to send their private key")
            print("and only use this spend bundle if they seem non-responsive.")
            print(
                f"Warning: after {clawback_delay_seconds} s they can claw back the XCH"
            )
            print()
            if ui_should_send_spend_bundle():
                try_to_push_tx(sweep_spend_bundle, sweep_puzzle_hash)

        if remote_secret:
            clean_spend_bundle = handle_remote_secret(
                coin_spend,
                message,
                remote_secret,
                s,
                synthetic_offset,
                parent_coin_id,
                xch_amount_mojos,
                total_pubkey,
                clawback_delay_seconds,
                clawback_public_key,
                sweep_receipt_hash,
                sweep_public_key,
                conditions,
            )
            print()
            if ui_should_send_spend_bundle():
                try_to_push_tx(clean_spend_bundle, sweep_puzzle_hash)


def handle_sweep_preimage(
    my_secret,
    puzzle_hash,
    parent_coin_id,
    xch_amount_mojos,
    fee_amount_mojos,
    total_pubkey,
    clawback_delay_seconds,
    clawback_public_key,
    sweep_receipt_hash,
    sweep_public_key,
    conditions,
    sweep_preimage,
):
    spend_bundle = generate_spendbundle(
        parent_coin_id,
        xch_amount_mojos,
        fee_amount_mojos,
        total_pubkey,
        clawback_delay_seconds,
        clawback_public_key,
        sweep_receipt_hash,
        sweep_public_key,
        conditions,
        sweep_preimage,
    )

    coin = Coin(parent_coin_id, puzzle_hash, xch_amount_mojos + fee_amount_mojos)
    message = (
        puzzle_for_conditions(conditions).get_tree_hash()
        + coin.name()
        + ADDITIONAL_DATA
    )

    private_key = private_key_for_secret(my_secret)
    total_sig = blspy.AugSchemeMPL.sign(private_key, message)
    spend_bundle = SpendBundle(spend_bundle.coin_spends, total_sig)

    spend_bundle_hex = bytes(spend_bundle).hex()
    print(f"sweep spend bundle: {spend_bundle_hex}")
    print()
    print("Your counterparty should share their (disposable) private key")
    print("with you now. If your counterparty disappears before sending it,")
    print("you can use the spend bundle above as a last resort.")
    print()
    return spend_bundle


def handle_remote_secret(
    coin_spend,
    message,
    remote_secret,
    my_secret,
    synthetic_offset,
    parent_coin_id,
    xch_amount_mojos,
    total_pubkey,
    clawback_delay_seconds,
    clawback_public_key,
    sweep_receipt_hash,
    sweep_public_key,
    conditions,
):
    total_secret = remote_secret + my_secret + synthetic_offset

    total_private_key = private_key_for_secret(total_secret)

    # build local signatures

    total_sig = blspy.AugSchemeMPL.sign(total_private_key, message)
    clean_spend_bundle = SpendBundle([coin_spend], total_sig)
    spend_bundle_hex = bytes(clean_spend_bundle).hex()
    print(f"clean spend bundle: {spend_bundle_hex}")
    print()
    print("Use the spend bundle above because it's smaller and is")
    print("indistinguishable from standard spend, so will give")
    print("the participants (you) more privacy.")
    return clean_spend_bundle


def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        prices_future = executor.submit(lookup_xch_prices)
        logfile, secret_key = ui_get_logfile()

    prices = prices_future.result()
    btc_amount, xch_amount, fee_amount = ui_get_amounts(logfile, prices)
    xch_amount_mojos = int((xch_amount) * Decimal(1e12))
    fee_amount_mojos = int((fee_amount) * Decimal(1e12))
    which_way = ui_choose(logfile)

    f = have_xch_want_btc if which_way == 1 else have_btc_want_xch
    f(logfile, secret_key, btc_amount, xch_amount_mojos, fee_amount_mojos)


if __name__ == "__main__":
    main()

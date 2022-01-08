This project defines a protocol for trustlessly swapping XCH and BTC using bitcoin lightning network payments.

Requirements
------------

- Chia Wallet (XCH)
- Bitcoin lightning wallet satisfying the following:
  - supports viewing the pre-image receipt (if selling BTC)
  - lightning payment requests that are valid for at least five minutes (if selling XCH) to give the XCH time to confirm.

Wallets Tested
--------------

Lightning:
- [Muun](https://muun.com/) confirmed on iOS to work in both directions
- ~~[BlueWallet](https://bluewallet.io/)~~ confirmed *not* working, as BlueWallet to BlueWallet payments do not reveal the pre-image needed to sweep the XCH funds
- ~~[Strike](https://strike.me/en/)~~ confirmed *not* working. There's no way to see the receipt pre-image, and the 57s timeout for payment requests is too low.

XCH:
- [Nucle](https://apps.apple.com/us/app/nucle-chia-crypto-wallet/id1582583173) has been confirmed to work in both directions
- the official [Chia](https://chia.net/) wallet should work although it hasn't been confirmed


Install
-------

Create and activate a virtualenv (first two lines), then install.

```
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install chiaswap
```

Use
---

Find a counterparty and negotiate the exchange quantities. Run the script.

```
$ xchswap
```

Answer the questions.

If you are claiming XCH (either through clawback for a failed swap or on the XCH receiving end of a completed swap), you will be given a `SpendBundle` hex dump. You can push that to the network using the `pushtx` tool.

```
$ source venv/bin/activate  # if you're not in the venv yet
$ pushtx 000000012...(lots of SpendBundle hex)...f4
```

The `pushtx` tool is a bit of a hack at the moment, and the output is not great. Use an explorer to verify the spend is in the mempool (the tool prints the coin ids that are being spent).


How It Works
------------

A lightning network payment request includes a pre-image of a secret value which is revealed atomically when the request is paid. Essentially, you're buying the pre-image of a secret.

If this same secret is also bound to another asset (in this case, XCH) you can then take that pre-image to claim the other asset. This is also how bitcoin [submarine swaps](https://docs.lightning.engineering/the-lightning-network/lightning-overview/understanding-submarine-swaps) work.


Custom ChiaLisp
---------------

A custom puzzle `p2_delayed_or_preimage` acts as an extension of `p2_delegated_puzzle_or_hidden_puzzle`. It takes *two* public keys: one for each counterparty. It commits to the hash of the pre-image, both public keys, and a clawback timeout (24 hours for now).

There are two payment paths in `p2_delayed_or_preimage`:

- after the clawback timeout using the XCH holder's key
- with the pre-image reveal using the BTC holder's key

Each of these uses `p2_delegated_puzzle_or_hidden_puzzle` internally.

The protocol locks XCH into a standard `p2_delegated_puzzle_or_hidden_puzzle` puzzle with `p2_delayed_or_preimage` as the hidden puzzle. The delegated puzzle is tied to the sum of the two participants public key, so one party can grant the XCH to the other by revealing their private key, allowing the other to make a spend that looks just like a "standard" chia spend.


Protocol Summary
----------------

We call the participants XCH and BTC
  - XCH has chia and wants bitcoin
  - BTC has bitcoin and wants chia

1. XCH & BTC create disposable private keys, and exchange corresponding signed public keys. They are signed to prove the private key is held; otherwise, the second to reveal a pubkey could do a subtraction attack.

2. XCH generates and shares a lightning invoice. The lightning invoice contains the hash of a secret. That value, along with the public keys and the clawback timeout (defaulting to 24 hours) is used to generate a chia address.

3. XCH sends coins to the chia address.

  - if BTC decides not to go through with the transaction, instead of paying the lightning invoice, BTC can share the disposable private key to XCH can claw back the funds immediately without waiting for the timeout.

  - if BTC vanishes, XCH can claw back these coins after the clawback timeout.

4. BTC waits for sufficient confirmations of the XCH coin, then pays the lightning invoice, revealing the secret. This secret can be used to claim the coins if XCH vanishes, so step 5 is optional.

5. XCH sees the invoice has been paid, and shares the disposable private key corresponding to his public key. BTC uses this key along with their own to claim the XCH using the "clean" case, which is indistinguishable from a standard XCH spend.


Open Questions
--------------

Is a 24 hour clawback timeout enough time? Is it too much time? What do bitcoin lightning payment failure cases look like?

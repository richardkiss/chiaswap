This project defines a protocol for trustlessly swapping XCH and BTC using bitcoin lightning network payments.

Requirements
------------

You will need a wallet that hold XCH and a bitcoin lightning wallet that supports viewing the pre-image receipt (if selling BTC) and lightning payment requests that are valid for at least ten minutes (if selling XCH) to give the XCH time to confirm.

Lightning:
- BlueWallet has been confirmed to work in both directions

XCH:
- Nucle has been confirmed to work in both directions


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
$ python chiaswap.py
```

Answer the questions.


HOW IT WORKS
------------

A lightning network payment request includes a pre-image of a secret value which is revealed atomically when the request is paid. Essentially, you're buying for the pre-image of a secret.

If this same secret is also bound to another asset -- in this case, XCH -- you can then take that pre-image to claim the other asset. This is also how bitcoin "submarine swaps" work.


p2_delayed_or_preimage.cl
-------------------------

A custom puzzle `p2_delayed_or_preimage.cl` acts as an extension of `p2_delegated_puzzle_or_hidden_puzzle.cl`. It takes *two* public keys: one for the XCH holder, and one for the pre-image holder. It commits to the hash of the pre-image, both public keys, and the timeout after which the original XCH holder can claw back the funds.

So the protocol involves locking up the XCH into a standard `p2_delegated_puzzle_or_hidden_puzzle.cl` puzzle as the hidden puzzle. The delegated puzzle is tied to the sum of the two participants public key.


Protocol Summary
----------------

We call the participants XCH and BTC: XCH has Chia and wants bitcoin, and BTC has bitcoin and wants Chia (so participant X has X and wants the other).

Step 1: XCH & BTC create disposable private keys, and exchange corresponding signed public keys. They are signed to prove the private key is held; otherwise, the second to reveal a pubkey could do a subtraction attack.

Step 2: XCH generates and shares a lightning invoice. The lightning invoice contains the hash of a secret. That value, along with the public keys and the clawback timeout (defaulting to 24 hours) is used to generate a chia address.

Step 3: XCH sends coins to the chia address.

If BTC decides not to go through with the transaction, instead of paying the lightning invoice, BTC can share the disposable private key to XCH can claw back the funds immediately without waiting for the timeout.

If BTC vanishes, XCH can claw back these coins after the clawback timeout.

Step 4: BTC waits for sufficient confirmations, then pays the lightning invoice, revealing the secret. (This secret can be used to claim the coins if XCH vanishes.)

Step 5: XCH sees the invoice has been paid, and shares the disposable private key corresponding to his public key. BTC uses this key along with their own to claim the XCH using the "clean" case, which is indistinguishable from a standard spend.

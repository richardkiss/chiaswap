from contextlib import ExitStack
from importlib import resources

import argparse
import asyncio
import socket
import ssl

from aiohttp import (
    ClientSession,
    ClientTimeout,
    WSMessage,
)
from chia.protocols.protocol_message_types import ProtocolMessageTypes
from chia.protocols.shared_protocol import Handshake
from chia.protocols import wallet_protocol
from chia.server.outbound_message import Message, make_msg
from chia.server.server import NodeType
from chia.types.spend_bundle import SpendBundle
from chia.util.ints import uint16, uint8


DNS_INTRODUCER_HOSTNAME = "dns-introducer.chia.net"

DEBUG_PEER_PROTOCOL = 0


def remote_host_ipv4():
    r = socket.getaddrinfo(DNS_INTRODUCER_HOSTNAME, 8444)
    for _ in set(r):
        t = _[4][0]
        if _[0] == socket.AddressFamily.AF_INET6:
            t = f"[{t}]"
        yield t


def get_ssl_context():
    file_stack = ExitStack()
    certs_dir = resources.files("certs")

    def certfile(file_name):
        return file_stack.enter_context(resources.as_file(certs_dir / file_name))

    chia_ca_crt_path = certfile("chia_ca.crt")
    crt_path = certfile("public_wallet.crt")
    key_path = certfile("public_wallet.key")

    ssl_context = ssl._create_unverified_context(
        purpose=ssl.Purpose.SERVER_AUTH, cafile=str(chia_ca_crt_path)
    )
    ssl_context.check_hostname = False
    ssl_context.load_cert_chain(certfile=str(crt_path), keyfile=str(key_path))
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    # we've read the key and crt files, so they can be trashed now
    file_stack.close()

    return ssl_context


async def push_tx(spend_bundle: SpendBundle):
    ssl_context = get_ssl_context()
    jobs = []
    for remote_host in remote_host_ipv4():
        job = asyncio.create_task(
            push_tx_to_host(ssl_context, spend_bundle, remote_host, 8444)
        )
        jobs.append(job)
    d = {}
    while 1:
        done, pending = await asyncio.wait(jobs, return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            try:
                rv = t.result()
            except Exception as ex:
                rv = str(ex)
            if DEBUG_PEER_PROTOCOL:
                d_key = rv
            else:
                # simplify output to "ok" and "failed"
                d_key = "ok" if "ack.None" == rv else "failed"
            d[d_key] = d.setdefault(d_key, 0) + 1
        lp = len(pending)
        d["pending"] = lp
        if lp == 0:
            del d["pending"]
        s = ", ".join("%s: %d" % (k, v) for k, v in sorted(d.items()))
        print(f"{s}                  ", end="\r")
        if len(pending) == 0:
            break
        jobs = list(pending)
    print()
    return all(_ not in d.keys() for _ in ["ack.None", "ok"])


def make_outbound_handshake_blob() -> bytes:
    network_id = "mainnet"
    protocol_version = "0.0.33"
    chia_full_version_str = "1.0.0.0"
    server_port = 1023
    node_type = NodeType.WALLET
    capabilities = [(1, "1")]
    handshake = Handshake(
        network_id,
        protocol_version,
        chia_full_version_str,
        uint16(server_port),
        uint8(node_type),
        capabilities,
    )
    outbound_handshake = make_msg(ProtocolMessageTypes.handshake, handshake)
    return bytes(outbound_handshake)


def make_send_transaction_blob(spend_bundle: SpendBundle) -> bytes:
    msg = make_msg(
        ProtocolMessageTypes.send_transaction,
        wallet_protocol.SendTransaction(spend_bundle),
    )
    return bytes(msg)


async def push_tx_to_host(
    ssl_context, spend_bundle: SpendBundle, remote_host, remote_port
):
    ws = None
    session = None
    try:
        timeout = ClientTimeout(total=10)
        session = ClientSession(timeout=timeout)

        url = f"wss://{remote_host}:{remote_port}/ws"
        # print(f"trying {url}")

        ws = await session.ws_connect(
            url,
            autoclose=True,
            autoping=True,
            heartbeat=60,
            ssl=ssl_context,
            max_msg_size=100 * 1024 * 1024,
        )

        outbound_handshake_blob = make_outbound_handshake_blob()
        await ws.send_bytes(outbound_handshake_blob)

        response: WSMessage = await ws.receive()
        # print(response)
        data = response.data
        full_message_loaded: Message = Message.from_bytes(data)
        message_type = ProtocolMessageTypes(full_message_loaded.type).name
        # print(message_type)
        # print(full_message_loaded)

        # breakpoint()
        send_transaction_blob = make_send_transaction_blob(spend_bundle)
        await ws.send_bytes(send_transaction_blob)
        rv = "failed"
        while 1:
            response: WSMessage = await ws.receive()
            if response.type == 8:  # WSMsgType.CLOSE
                v = None
                break
            if response.type != 2:  # WSMsgType.BINARY
                v = None
                break
            # print(response)
            data = response.data
            full_message_loaded: Message = Message.from_bytes(data)
            message_type = ProtocolMessageTypes(full_message_loaded.type).name
            # print(message_type)
            if str(message_type) == "transaction_ack":
                v = wallet_protocol.TransactionAck.from_bytes(full_message_loaded.data)
                ack_map = {
                    "ALREADY_INCLUDING_TRANSACTION": "included",
                    "DOUBLE_SPEND": "double-spend",
                    "NO_TRANSACTIONS_WHILE_SYNCING": "catching-up",
                    "ASSERT_SECONDS_RELATIVE_FAILED": "not-valid-yet",
                }
                msg = ack_map.get(v.error, v.error)
                rv = f"ack.{msg}"
                break
            # print(full_message_loaded)
        # print(v)
        # breakpoint()
        # print(v)
        if rv == "ack.3":
            print(v)
            # breakpoint()
            pass
        await ws.close()
        await session.close()
        return rv
    except Exception as ex:
        if ws is not None:
            await ws.close()
            # breakpoint()
        if session is not None:
            await session.close()
        exception_map = [
            ("Cannot connect to host", "no-connection"),
            ("ConnectionResetError", "reset"),
            ("TimeoutError", "timeout"),
            ("ClientConnectorError", "client-error"),
            ("ServerDisconnectedError", "peer-dropped"),
            ("ClientConnectorCertificateError", "bad-cert"),
        ]
        msg = repr(ex)
        for s, r in exception_map:
            if msg.startswith(s):
                return r
        if DEBUG_PEER_PROTOCOL:
            print(f"unknown `msg`, consider diagnosing and adding code for this case")
            print("Dropping into debugger; enter `c` to continue `pushtx`")
            breakpoint()
        return msg


def show_coins_spent(spend_bundle):
    for coin_spend in spend_bundle.coin_spends:
        coin = coin_spend.coin
        print(f"spending coin id 0x{coin.name().hex()}")
    print()


async def async_main(args, parser):
    spend_bundle = args.spend_bundle[0]
    if args.debug:
        spend_bundle.debug()
    show_coins_spent(spend_bundle)
    if not args.dry_run:
        await push_tx(spend_bundle)


def spend_bundle_from_hex(h):
    return SpendBundle.from_bytes(bytes.fromhex(h))


def create_parser():
    parser = argparse.ArgumentParser(description="Process some integers.")
    parser.add_argument(
        "spend_bundle",
        metavar="SPENDBUNDLE_HEX",
        type=spend_bundle_from_hex,
        nargs=1,
        help="the `SpendBundle` as hex",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="show debug information for spendbundle",
    )
    parser.add_argument(
        "-n",
        "--dry-run",
        action="store_true",
        help="don't actually send `SpendBundle` to the network",
    )
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    return asyncio.run(async_main(args, parser))


if __name__ == "__main__":
    main()

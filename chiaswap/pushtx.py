import argparse
import asyncio
import os
import socket
import tempfile

from pathlib import Path

from aiohttp import (
    ClientSession,
    ClientTimeout,
    WSMessage,
)
from chia.cmds.init_funcs import create_all_ssl
from chia.protocols.protocol_message_types import ProtocolMessageTypes
from chia.protocols.shared_protocol import Handshake
from chia.protocols import wallet_protocol
from chia.server.outbound_message import Message, make_msg
from chia.server.server import ssl_context_for_client, NodeType
from chia.types.spend_bundle import SpendBundle
from chia.util.ints import uint16, uint8


DNS_INTRODUCER_HOSTNAME = "dns-introducer.chia.net"


def remote_host_ipv4():
    r = socket.getaddrinfo(DNS_INTRODUCER_HOSTNAME, 8444)
    for _ in set(r):
        t = _[4][0]
        if _[0] == socket.AddressFamily.AF_INET6:
            t = f"[{t}]"
        yield t


def make_ssl_path():
    # wow, this code sucks, but it's mostly due to the code in the chia module
    # not being very flexible
    temp_dir = tempfile.TemporaryDirectory()
    root_path = Path(temp_dir.name)
    ssl_dir = root_path / "config" / "ssl"
    os.makedirs(ssl_dir)
    create_all_ssl(root_path)
    # we have to keep `temp_dir` around because the contents
    # are deleted when it's garbage-collected
    return temp_dir, root_path


def get_ssl_context():
    _temp_dir, root_path = make_ssl_path()

    ssl_path = root_path / "config" / "ssl"
    ca_path = ssl_path / "ca"
    wallet_path = ssl_path / "wallet"
    chia_ca_crt_path = ca_path / "chia_ca.crt"
    chia_ca_key_path = ca_path / "chia_ca.key"

    crt_path = wallet_path / "public_wallet.crt"
    key_path = wallet_path / "public_wallet.key"

    ssl_context = ssl_context_for_client(
        chia_ca_crt_path, chia_ca_key_path, crt_path, key_path
    )
    # we have to keep `temp_dir` around because the contents
    # are deleted when it's garbage-collected
    ssl_context.temp_dir = _temp_dir
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
            d[rv] = d.setdefault(rv, 0) + 1
        lp = len(pending)
        d["pending"] = lp
        if lp == 0:
            del d["pending"]
        s = ", ".join("%s: %d" % (k, v) for k, v in sorted(d.items()))
        print(s)
        if len(pending) == 0:
            break
        jobs = list(pending)


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
        await ws.send_bytes(bytes(outbound_handshake))

        response: WSMessage = await ws.receive()
        # print(response)
        data = response.data
        full_message_loaded: Message = Message.from_bytes(data)
        message_type = ProtocolMessageTypes(full_message_loaded.type).name
        # print(message_type)
        # print(full_message_loaded)

        # breakpoint()
        msg = make_msg(
            ProtocolMessageTypes.send_transaction,
            wallet_protocol.SendTransaction(spend_bundle),
        )
        await ws.send_bytes(bytes(msg))
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
                # breakpoint()
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
        ]
        msg = repr(ex)
        for s, r in exception_map:
            if msg.startswith(s):
                return r
        print(f"unknown `msg`, consider diagnosing and adding code for this case")
        print("Dropping into debugger; enter `c` to continue `pushtx`")
        breakpoint()
        return msg


async def async_main(args, parser):
    spend_bundle = args.spend_bundle[0]
    if args.debug:
        spend_bundle.debug()
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

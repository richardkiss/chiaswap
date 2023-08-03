from dataclasses import dataclass
from enum import IntEnum
from typing import Any, List, Optional, Tuple

import io
import struct

from chia_base.core import SpendBundle

uint16 = uint8 = int
bytes32 = bytes


NodeType_WALLET = 6


@dataclass(frozen=True)
class Message:
    # one of ProtocolMessageTypes
    type: uint8
    # message id
    id: Optional[uint16]
    # Message data for that type
    data: bytes

    def __bytes__(self):
        s = io.BytesIO()
        write_uint8(s, int(self.type))
        write_none(s)
        write_bytes(s, self.data)
        return s.getvalue()

    @classmethod
    def from_bytes(cls, blob: bytes) -> "Message":
        s = io.BytesIO(blob)
        message_type = s.read(1)[0]
        has_some = s.read(1)[0]
        id = struct.unpack("!H", s.read(2))[0] if has_some else None
        data = s.read()[4:]
        return Message(message_type, id, data)


class ProtocolMessageTypes(IntEnum):
    handshake = 1
    send_transaction = 48
    transaction_ack = 49
    new_peak_wallet = 50


@dataclass(frozen=True)
class Handshake:
    network_id: str
    protocol_version: str
    software_version: str
    server_port: uint16
    node_type: uint8
    capabilities: List[Tuple[uint16, str]]

    def __bytes__(self):
        s = io.BytesIO()
        write_str(s, self.network_id)
        write_str(s, self.protocol_version)
        write_str(s, self.software_version)
        write_uint16(s, self.server_port)
        write_uint8(s, self.node_type)

        def write_capability(f, o):
            write_uint16(f, o[0])
            write_str(f, o[1])

        write_list(s, self.capabilities, write_capability)
        return s.getvalue()


def write_str(f, s: str):
    write_uint32(f, len(s))
    f.write(s.encode("utf8"))


def write_uint8(f, v: int):
    f.write(struct.pack("!B", v))


def write_uint16(f, v: int):
    f.write(struct.pack("!H", v))


def write_uint32(f, v: int):
    f.write(struct.pack("!L", v))


def write_empty_list(f):
    write_uint16(f, 0)


def write_none(f):
    write_uint8(f, 0)


def write_list(f, items, write_item_f):
    write_uint32(f, len(items))
    for item in items:
        write_item_f(f, item)


def write_bytes(f, blob):
    write_uint32(f, len(blob))
    f.write(blob)


@dataclass(frozen=True)
class TransactionAck:
    txid: bytes32
    status: uint8  # MempoolInclusionStatus
    error: Optional[str]

    @classmethod
    def from_bytes(cls, blob: bytes) -> "TransactionAck":
        txid = blob[:32]
        status = blob[32]
        has_err = blob[33]
        error = blob[38:].decode() if has_err else None
        return cls(txid, status, has_err)


@dataclass(frozen=True)
class SendTransaction:
    transaction: SpendBundle

    def __bytes__(self):
        return bytes(self.transaction)


class wallet_protocol:
    TransactionAck = TransactionAck
    SendTransaction = SendTransaction


def make_msg(msg_id: int, message: Any) -> Message:
    message_blob = bytes(message)
    return Message(msg_id, None, message_blob)

# Copyright (c) 2025 iiPython

import json
import typing
from enum import Enum
from base64 import b64encode, b64decode

def encode(data: bytes) -> str:
    return b64encode(data).decode()

def decode(data: str) -> bytes:
    return b64decode(data.encode())

type PacketData = dict[str, typing.Any]

class PacketType(Enum):
    AUTH = 1
    ACK  = 2

def build_packet(type: PacketType, data: PacketData = {}) -> str:
    return json.dumps({"type": type.name, "data": data})

def extract_packet(packet: str) -> tuple[PacketType, PacketData] | None:
    try:
        decoded: PacketData = json.loads(packet)
        return PacketType[decoded["type"]], decoded["data"]

    except json.JSONDecodeError:
        return None

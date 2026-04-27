# Copyright (c) 2026 iiPython

import struct
import secrets
from enum import IntEnum

RADON_MAGIC    = b"RDN\xA7"
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
TEXT_ENCODING  = "utf-8"

type ParamValue = str | int | bool | bytes

class HeaderType(IntEnum):
    AUTHORIZATION = 0x01
    CLIENT_ID     = 0x02

def u8(x: int | bytes) -> bytes:  return struct.pack(">B", x)
def u16(x: int | bytes) -> bytes: return struct.pack(">H", x)
def u32(x: int | bytes) -> bytes: return struct.pack(">I", x)
def u64(x: int | bytes) -> bytes: return struct.pack(">Q", x)

def bytes_plus_length(data: bytes, size: int = 2) -> bytes:
    return u16(len(data)) if size == 2 else u32(len(data)) + data

def encode_string(string: str) -> bytes:
    return bytes_plus_length(string.encode(TEXT_ENCODING))

class Frame:
    def __init__(
        self,
        packet_type: int,
        version_major: int = PROTOCOL_MAJOR,
        version_minor: int = PROTOCOL_MINOR,
        flags: int = 0,
        packet_id: int | None = None
    ) -> None:
        self.packet_type = packet_type
        self.version = (version_major, version_minor)
        self.flags = flags
        self.packet_id = packet_id or secrets.randbits(64)

    def build_payload(self) -> bytes:
        return b""

    def build(self) -> bytes:
        payload = self.build_payload()
        return b"".join([
            RADON_MAGIC,
            u8(self.version[0]),
            u8(self.version[1]),
            u8(self.packet_type),
            u8(self.flags),
            u64(self.packet_id),
            u32(len(payload)),
            payload
        ])

class RetrieveFrame(Frame):
    def __init__(self, path: str, headers: dict[HeaderType, str] = {}, params: dict[str, ParamValue] = {}, **kwargs) -> None:
        super().__init__(0x01, **kwargs)
        self.path, self.headers, self.params = path, headers, params

    def build_payload(self) -> bytes:
        payload = bytearray(encode_string(self.path))

        # Headers
        payload.extend(u16(len(self.headers)))
        for header_id, header_value in self.headers.items():
            payload.extend(u8(header_id) + encode_string(header_value))

        # Parameters
        payload.extend(u16(len(self.params)))
        for param_name, param_value in self.params.items():
            param_type, encoded_value = self.encode_param(param_value)
            payload.extend(encode_string(param_name) + u8(param_type))
            payload.extend(bytes_plus_length(encoded_value))

        return bytes(payload)

    def encode_param(self, value: ParamValue) -> tuple[int, bytes]:
        if isinstance(value, str):
            return 1, value.encode("utf-8")

        if isinstance(value, bool):
            return 3, u8(int(value))

        if isinstance(value, int):
            return 2, u32(value)

        if isinstance(value, bytes):
            return 4, value

        raise ValueError("encode_param failed due to an invalid value type!")

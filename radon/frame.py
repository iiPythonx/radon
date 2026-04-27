# Copyright (c) 2026 iiPython

import struct
import typing
import secrets
import asyncio

RADON_MAGIC    = b"RDN\xA7"
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
TEXT_ENCODING  = "utf-8"

type ParamValue = str | int | bool | bytes

T = typing.TypeVar("T", bound = "Frame")

def u8(x: int | bytes) -> bytes:  return struct.pack(">B", x)
def u16(x: int | bytes) -> bytes: return struct.pack(">H", x)
def u32(x: int | bytes) -> bytes: return struct.pack(">I", x)
def u64(x: int | bytes) -> bytes: return struct.pack(">Q", x)

def read_u8(view: memoryview, offset: int) -> tuple[int, int]:
    return view[offset], offset + 1

def read_u16(view: memoryview, offset: int) -> tuple[int, int]:
    return struct.unpack_from(">H", view, offset)[0], offset + 2

def read_u32(view: memoryview, offset: int) -> tuple[int, int]:
    return struct.unpack_from(">I", view, offset)[0], offset + 4

def read_bytes(view: memoryview, offset: int, length: int) -> tuple[bytes, int]:
    return view[offset:offset + length].tobytes(), offset + length

def read_string(view: memoryview, offset: int) -> tuple[str, int]:
    length, offset = read_u16(view, offset)
    data, offset = read_bytes(view, offset, length)
    return data.decode("utf-8"), offset

def bytes_plus_length(data: bytes, size: int = 2) -> bytes:
    return (u16(len(data)) if size == 2 else u32(len(data))) + data

def encode_string(string: str) -> bytes:
    return bytes_plus_length(string.encode(TEXT_ENCODING))

class Frame:
    TYPE = 0x00

    def __init__(
        self,
        packet_type: int,
        version_major: int = PROTOCOL_MAJOR,
        version_minor: int = PROTOCOL_MINOR,
        packet_flags: int = 0,
        packet_id: int | None = None
    ) -> None:
        self.packet_type = packet_type
        self.version = (version_major, version_minor)
        self.flags = packet_flags
        self.packet_id = packet_id or secrets.randbits(64)

    def build_payload(self) -> bytes:
        return b""

    @classmethod
    def from_payload(cls, view: memoryview, **kwargs) -> typing.Self:
        return cls(**kwargs)

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
    TYPE = 0x01

    def __init__(self, path: str, params: dict[str, ParamValue] = {}, body: bytes = b"", **kwargs) -> None:
        super().__init__(self.TYPE, **kwargs)
        self.path, self.params, self.body = path, params, body

    def build_payload(self) -> bytes:
        payload = bytearray(encode_string(self.path))

        # Parameters
        payload.extend(u16(len(self.params)))
        for param_name, param_value in self.params.items():
            param_type, encoded_value = self.encode_param(param_value)
            payload.extend(encode_string(param_name) + u8(param_type))
            payload.extend(bytes_plus_length(encoded_value))

        # Body
        payload.extend(bytes_plus_length(self.body, size = 4))
        return bytes(payload)

    @staticmethod
    def encode_param(value: ParamValue) -> tuple[int, bytes]:
        if isinstance(value, str):
            return 1, value.encode("utf-8")

        if isinstance(value, bool):
            return 3, u8(int(value))

        if isinstance(value, int):
            return 2, u32(value)

        if isinstance(value, bytes):
            return 4, value

        raise ValueError("encode_param failed due to an invalid value type!")

    @staticmethod
    def decode_param(param_type: int, param_value: bytes) -> ParamValue:
        match param_type:
            case 0x01:
                return param_value.decode(TEXT_ENCODING)

            case 0x02:
                return struct.unpack(">I", param_value)[0]

            case 0x03:
                return param_value[0] != 0
                
            case 0x04:
                return param_value

            case _:
                raise ValueError("decode_param failed due to an invalid value type!")

    @classmethod
    def from_payload(cls, view: memoryview, **kwargs) -> typing.Self:
        offset = 0

        # Read path
        path, offset = read_string(view, offset)

        # Read parameters
        params, (param_count, offset) = {}, read_u16(view, offset)
        for _ in range(param_count):
            param_name, offset = read_string(view, offset)
            param_type, offset = read_u8(view, offset)
            size, offset = read_u16(view, offset)
            raw_value, offset = read_bytes(view, offset, size)
            params[param_name] = cls.decode_param(param_type, raw_value)

        # Read body
        body_size, offset = read_u32(view, offset)
        body, offset = read_bytes(view, offset, body_size)

        return cls(path, params, body, **kwargs)

FRAME_MAP = {
    0x01: RetrieveFrame
}

async def read_from_stream(stream: asyncio.StreamReader) -> Frame | None:
    if await stream.readexactly(4) != RADON_MAGIC:
        raise ValueError("We've received something that isn't a Radon frame!")

    version_major, version_minor, packet_type, packet_flags = \
        [int(byte) for byte in await stream.readexactly(4)]

    packet_id = struct.unpack(">Q", await stream.readexactly(8))[0]
    payload_size = struct.unpack(">I", await stream.readexactly(4))[0]

    packet = {
        "version_major": version_major,
        "version_minor": version_minor,
        "packet_flags": packet_flags,
        "packet_id": packet_id
    }

    # Build frame
    frame = FRAME_MAP.get(packet_type)
    if frame is not None:
        frame = frame.from_payload(memoryview(await stream.readexactly(payload_size)), **packet)

    return frame

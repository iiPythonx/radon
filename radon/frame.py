# Copyright (c) 2026 iiPython

import struct
import typing
import secrets
from enum import IntEnum

RADON_MAGIC    = b"RDN\xA7"
PROTOCOL_MAJOR = 1
PROTOCOL_MINOR = 0
TEXT_ENCODING  = "utf-8"

type ParamValue = str | int | bool | bytes

T = typing.TypeVar("T", bound = "Frame")

class HeaderType(IntEnum):
    AUTHORIZATION = 0x01
    CLIENT_ID     = 0x02

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
    _frame_map: dict[int, type["Frame"]] = {}

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

    @classmethod
    def connect(cls, frame_cls: type[T]) -> type[T]:
        cls._frame_map[frame_cls.TYPE] = frame_cls
        return frame_cls

    @classmethod
    def parse(cls, data: bytes) -> "Frame":
        view, offset = memoryview(data), 0

        # Confirm header is valid
        if view[:4] != RADON_MAGIC:
            raise ValueError("The provided data is not a valid Radon frame!")

        offset += 4

        # Parse frame data
        version_major = view[offset]
        version_minor = view[offset + 1]
        packet_type   = view[offset + 2]
        packet_flags  = view[offset + 3]
        offset += 4

        packet_id = struct.unpack_from(">Q", view, offset)[0]
        payload_size = struct.unpack_from(">I", view, offset + 8)[0]
        offset += 12

        # Load correct frame class
        frame_constructor = cls._frame_map.get(packet_type)
        if frame_constructor is None:
            raise ValueError(f"Frame.parse received an unknown packet type of {packet_type}!")

        return frame_constructor.from_payload(
            view[offset:offset + payload_size],
            version_major = version_major,
            version_minor = version_minor,
            packet_flags = packet_flags,
            packet_id = packet_id
        )

@Frame.connect
class RetrieveFrame(Frame):
    TYPE = 0x01

    def __init__(self, path: str, headers: dict[HeaderType, str] = {}, params: dict[str, ParamValue] = {}, **kwargs) -> None:
        super().__init__(self.TYPE, **kwargs)
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

        # Read headers
        headers, (header_count, offset) = {}, read_u16(view, offset)
        for _ in range(header_count):
            header_type, offset = read_u8(view, offset)
            size, offset = read_u16(view, offset)
            value, offset = read_bytes(view, offset, size)
            headers[header_type] = value.decode(TEXT_ENCODING)

        # Read parameters
        params, (param_count, offset) = {}, read_u16(view, offset)
        for _ in range(param_count):
            param_name, offset = read_string(view, offset)
            param_type, offset = read_u8(view, offset)
            size, offset = read_u16(view, offset)
            raw_value, offset = read_bytes(view, offset, size)
            params[param_name] = cls.decode_param(param_type, raw_value)

        return cls(path, headers, params, **kwargs)

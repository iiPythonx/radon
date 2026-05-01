# Copyright (c) 2026 iiPython

import gzip
import struct
import asyncio
import typing

RADON_SEPERATOR = b"\xA7"
TEXT_ENCODING = "utf-8"

FRAME_OPT_FETCH  = 0b10000000
FRAME_OPT_GZIP   = 0b01000000
FRAME_OPT_PARAMS = 0b00100000
FRAME_OPT_BODY   = 0b00010000
FRAME_OPT_IDENT  = 0b00001000

def u8(x: int | bytes) -> bytes:  return struct.pack(">B", x)
def u16(x: int | bytes) -> bytes: return struct.pack(">H", x)
def u32(x: int | bytes) -> bytes: return struct.pack(">I", x)
def u64(x: int | bytes) -> bytes: return struct.pack(">Q", x)

type Parameter = int | bool | str

class FrameIssue(Exception):
    pass

def encode_integer(value: int) -> tuple[int, bytes]:
    formats = [
        (2, ">b", -128, 127),
        (3, ">h", -32_768, 32_767),
        (4, ">i", -2_147_483_648, 2_147_483_647),
        (5, ">q", -9_223_372_036_854_775_808, 9_223_372_036_854_775_807),
    ]

    for type_id, fmt, lo, hi in formats:
        if lo <= value <= hi:
            return type_id, struct.pack(fmt, value)

    raise ValueError("provided integer value exceeds all possible sizes")

def decode_param(param_type: int, value: bytes) -> Parameter:
    match param_type:
        case 0:
            return value.decode(TEXT_ENCODING)

        case 1:
            return bool(struct.unpack(">B", value)[0])

        case 2 | 3 | 4 | 5:
            struct_type = "bhiq"[param_type - 2]
            return struct.unpack(f">{struct_type}", value)[0]

    raise ValueError("The parameter type provided was invalid!")

def encode_param(value: Parameter) -> tuple[int, bytes]:
    if isinstance(value, str):
        return 0, value.encode(TEXT_ENCODING)

    if isinstance(value, bool):
        return 1, u8(int(value))

    if isinstance(value, int):
        return encode_integer(value)

class Frame:
    def __init__(
        self,
        options: int = 0,
        identification: int | None = None,
        params: dict[str, Parameter] | None = None,
        body: bytes = b"",
        path: str | None = None,
    ) -> None:
        self.path, self.params, self.body, self.identification, self.options = \
            path, params, body, identification, options

    def __bytes__(self) -> bytes:
        for check, option in [(self.params, FRAME_OPT_PARAMS), (self.body, FRAME_OPT_BODY), (self.identification, FRAME_OPT_IDENT)]:
            if check:
                self.options |= option

        frame = bytearray(b"RDN" + u8(self.options))
        if self.options & FRAME_OPT_IDENT and self.identification is not None:
            frame.extend(u8(self.identification))

        if self.options & FRAME_OPT_FETCH and self.path is not None:
            frame.extend(u8(len(self.path)) + self.path.encode(TEXT_ENCODING))

        if self.params:
            frame.extend(u8(len(self.params)))
            for key, value in self.params.items():
                param_type, param_value = encode_param(value)
                size_hint, value_size = encode_integer(len(param_value))
                frame.extend(u8(param_type) + u8(len(key)) + key.encode(TEXT_ENCODING) + u8(size_hint) + value_size + param_value)

        if self.body:
            if self.options & FRAME_OPT_GZIP:
                self.body = gzip.compress(self.body)

            size_hint, body_size = encode_integer(len(self.body))
            frame.extend(u8(size_hint) + body_size + self.body)

        return bytes(frame)

    @classmethod
    async def from_stream(cls, stream: asyncio.StreamReader) -> typing.Self:
        if await stream.readexactly(3) != b"RDN":
            raise FrameIssue

        path, params, body, identification = None, {}, b"", None

        (options,) = struct.unpack(">B", await stream.readexactly(1))
        if options & FRAME_OPT_IDENT:
            (identification,) = struct.unpack(">B", await stream.readexactly(1))

        if options & FRAME_OPT_FETCH:
            (path_size,) = struct.unpack(">B", await stream.readexactly(1))
            path = (await stream.readexactly(path_size)).decode(TEXT_ENCODING)

        if options & FRAME_OPT_PARAMS:
            (param_count,) = struct.unpack(">B", await stream.readexactly(1))
            for _ in range(param_count):
                param_type, param_key_size = tuple(await stream.readexactly(2))
                param_name = (await stream.readexactly(param_key_size)).decode(TEXT_ENCODING)
                (size_hint,) = struct.unpack(">B", await stream.readexactly(1))
                param_size = decode_param(size_hint, await stream.readexactly([1, 2, 4, 8][size_hint - 2]))
                params[param_name] = decode_param(param_type, (await stream.readexactly(int(param_size))))

        if options & FRAME_OPT_BODY:
            (size_hint,) = struct.unpack(">B", await stream.readexactly(1))
            body_size = decode_param(size_hint, await stream.readexactly([1, 2, 4, 8][size_hint - 2]))

            body = await stream.readexactly(int(body_size))
            if options & FRAME_OPT_GZIP:
                body = gzip.decompress(body)

        return cls(options, identification, params, body, path)

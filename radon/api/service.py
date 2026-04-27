# Copyright (c) 2026 iiPython

import struct
import typing
import asyncio

from radon.frame import FRAME_MAP, RADON_MAGIC, T, Frame, RetrieveFrame
from radon.utils.logs import log

class Service:
    def __init__(self) -> None:
        self.callbacks: dict[int, list[tuple[typing.Callable, tuple[typing.Any, ...]]]] = {}

    def bind(self, frame_type: type[T], *args) -> typing.Callable:
        def internal(function: typing.Callable) -> None:
            self.callbacks.setdefault(frame_type.TYPE, [])
            self.callbacks[frame_type.TYPE].append((function, args))

        return internal

    async def handle_client(self, read_stream: asyncio.StreamReader, write_stream: asyncio.StreamWriter) -> None:
        log.info("client", "Connection opened!")

        async def abort() -> None:
            write_stream.close()
            await write_stream.wait_closed()

        # Read frame
        if await read_stream.readexactly(4) != RADON_MAGIC:
            raise ValueError("We've received something that isn't a Radon frame!")

        version_major, version_minor, packet_type, packet_flags = \
            [int(byte) for byte in await read_stream.readexactly(4)]

        packet_id = struct.unpack(">Q", await read_stream.readexactly(8))[0]
        payload_size = struct.unpack(">I", await read_stream.readexactly(4))[0]

        packet = {
            "version_major": version_major,
            "version_minor": version_minor,
            "packet_flags": packet_flags,
            "packet_id": packet_id
        }
        payload = memoryview(await read_stream.readexactly(payload_size))

        # Build frame
        frame = FRAME_MAP.get(packet_type)
        if frame is not None:
            frame = frame.from_payload(payload, **packet)

            # Handle frame
            response: Frame | None = None
            for callback, args in self.callbacks.get(frame.TYPE, []):
                if isinstance(frame, RetrieveFrame) and args[0] != frame.path:
                    continue

                response = await callback(frame)

            # Handle response
            if response is not None:
                write_stream.write(response.build())

        await abort()
        log.info("client", "Connection closed!")

    async def serve(self, host: str = "0.0.0.0", port: int = 7777) -> None:
        async with await asyncio.start_server(self.handle_client, host, port) as backend:
            await backend.serve_forever()

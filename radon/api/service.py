# Copyright (c) 2026 iiPython

import typing
import asyncio

from radon.frame import T, Frame, RetrieveFrame, read_from_stream
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
            log.info("client", "Connection closed!")

        frame = await read_from_stream(read_stream)
        if frame is None:
            return await abort()

        # Handle frame
        response: Frame | None = None
        for callback, args in self.callbacks.get(frame.TYPE, []):
            if isinstance(frame, RetrieveFrame) and args[0] != frame.path:
                continue

            response = await callback(frame)

        # Handle response
        if response is None:
            response = RetrieveFrame("", {"success": False}, "No route available on requested path.".encode())

        write_stream.write(response.build())
        await abort()

    async def serve(self, host: str = "0.0.0.0", port: int = 7777) -> None:
        async with await asyncio.start_server(self.handle_client, host, port) as backend:
            await backend.serve_forever()

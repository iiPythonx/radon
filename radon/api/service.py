# Copyright (c) 2026 iiPython

import typing
import asyncio

from radon.frame import T, Frame, FuckOffFrame, ResponseFrame, RetrieveFrame, read_from_stream
from radon.utils.logs import log

class Service:
    def __init__(self) -> None:
        self.callbacks: dict[int, list[tuple[typing.Callable, tuple[typing.Any, ...]]]] = {}

    @staticmethod
    def _log_frame(direction: typing.Literal["rx", "tx"], frame: Frame) -> None:
        log.network(direction, f"T: 0x0{frame.packet_type} | ID: {frame.packet_id:<20} | F: {frame.flags:<3} | V: {'.'.join(str(_) for _ in frame.version)}")

    def bind(self, frame_type: type[T], *args) -> typing.Callable:
        def internal(function: typing.Callable) -> None:
            self.callbacks.setdefault(frame_type.packet_type, [])
            self.callbacks[frame_type.packet_type].append((function, args))

        return internal

    async def handle_client(self, read_stream: asyncio.StreamReader, write_stream: asyncio.StreamWriter) -> None:
        log.info("client", "Connection opened!")

        async def abort() -> None:
            write_stream.close()
            await write_stream.wait_closed()
            log.info("client", "Connection closed!")

        while read_stream:
            try:
                frame = await read_from_stream(read_stream)
                if frame is None:
                    return await abort()

                self._log_frame("rx", frame)

                # Handle 0x03
                if isinstance(frame, FuckOffFrame):
                    return await abort()

            except asyncio.IncompleteReadError:
                log.warn("client", "Read was incomplete!")
                return await abort()

            # Handle frame
            response: Frame | None = None
            for callback, args in self.callbacks.get(frame.packet_type, []):
                if isinstance(frame, RetrieveFrame) and args[0] != frame.path:
                    continue

                response = await callback(frame)

            # Handle response
            if response is None:
                response = ResponseFrame({"success": False}, "No route available on requested path.".encode())

            write_stream.write(response.build())
            self._log_frame("tx", response)

        await abort()

    async def serve(self, host: str = "0.0.0.0", port: int = 7777) -> None:
        async with await asyncio.start_server(self.handle_client, host, port) as backend:
            await backend.serve_forever()

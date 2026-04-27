# Copyright (c) 2026 iiPython

import asyncio

from radon.frame import Frame, FuckOffFrame, ParamValue, RetrieveFrame, read_from_stream

class Client:
    def __init__(self) -> None:
        self.read_stream: asyncio.StreamReader
        self.write_stream: asyncio.StreamWriter

    async def connect(self, host: str, port: int = 7777) -> None:
        self.read_stream, self.write_stream = await asyncio.open_connection(host, port)

    async def retrieve(self, path: str, params: dict[str, ParamValue] = {}, body: bytes = b"") -> Frame | None:
        self.write_stream.write(RetrieveFrame(path, params, body).build())
        return await read_from_stream(self.read_stream)

    async def fuckoff(self) -> None:
        self.write_stream.write(FuckOffFrame().build())
        self.write_stream.close()
        await self.write_stream.wait_closed()

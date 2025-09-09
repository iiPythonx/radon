# Copyright (c) 2025 iiPython

# Modules
import typing
import asyncio
from enum import Enum
from argparse import ArgumentParser

from websockets import State, WebSocketException
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve

from radon import RADON_KNOWN_ROUTERS
from radon.utils.encoding import (
    build_packet, extract_packet, PacketType
)

from radon.comms import fetch_keys
from radon.utils.logs import log

# Initialization
class Mode(Enum):
    NODE   = 1
    ROUTER = 2

# Routing setup
type KeyHash = str

# Handle node
class RadonNode:
    def __init__(self, mode: Mode, port: int, pk_filename: str = "pk.bin") -> None:
        self.mode: Mode = mode
        self.port: int = port

        self.private_key, self.public_key = fetch_keys(pk_filename)
        self.routes: dict[KeyHash, list[KeyHash]] = {}

        log.info("node", f"Radon is starting up, active mode is {mode.name}.")
        log.info("node", f"\t-> Public: {self.public_key}")

    async def async_init(self) -> None:
        for public_key, (address, port) in RADON_KNOWN_ROUTERS.items():
            asyncio.create_task(self.mesh_with(address, port, public_key))

        await self.start_socket()

    async def process_packet(self, ptype: PacketType, payload: dict[str, typing.Any]) -> None:
        print(ptype, payload)

    async def mesh_with(self, address: str, port: int, public_key: str) -> None:
        if public_key == self.public_key:
            return log.info("mesh", f"Skipping {address}, because that's us")

        log.info("mesh", f"Attempting to mesh with {address}:{port}")

        socket, interval = None, 5
        while socket is None:
            try:
                socket = await connect(f"ws://{address}:{port}")

            except (ConnectionError, TimeoutError):
                await asyncio.sleep(interval)
                log.warn("mesh", f"Failed to mesh with {address}:{port}, trying again in {interval} seconds.")

                interval += 10

        await socket.send(build_packet(PacketType.AUTH, {"publicKey": self.public_key}))
        while socket.state == State.OPEN:
            message = extract_packet(str(await socket.recv()))
            if message is None:
                break

            await self.process_packet(*message)

        await socket.close()

    async def start_socket(self) -> None:
        async with serve(self.process_client, "0.0.0.0", self.port) as socket:
            log.info("node", f"Socket created and listening at http://127.0.0.1:{self.port}!")
            await socket.serve_forever()

    async def process_client(self, client: ServerConnection) -> None:
        try:
            async for message in client:
                message = extract_packet(str(message))
                if message is None:
                    break

                await self.process_packet(*message)

        except WebSocketException:
            log.info("router", "Websocket exception occured! Client has been killed.")

        await client.close()

# Handle main
if __name__ == "__main__":
    a = ArgumentParser()
    a.add_argument("-t", "--type", choices = ("node", "router"), required = True)
    a.add_argument("-p", "--port", type = int)

    args = a.parse_args()

    # Startup node
    node: RadonNode = RadonNode(Mode[args.type.upper()], port = args.port or 26104)
    asyncio.run(node.async_init())

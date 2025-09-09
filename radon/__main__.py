# Copyright (c) 2025 iiPython

# Modules
import typing
import asyncio
from enum import Enum
from dataclasses import dataclass
from argparse import ArgumentParser

from websockets import State, WebSocketException
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve

from radon import RADON_KNOWN_ROUTERS, KNOWN_ROUTER_KEYS
from radon.comms import PUBLIC_KEY
from radon.utils.logs import info
from radon.utils.encoding import (
    build_packet, extract_packet, PacketType
)

# Initialization
class Mode(Enum):
    NODE   = 1
    ROUTER = 2

# Routing setup
type KeyHash = str

# Handle node
class RadonNode:
    def __init__(self, mode: Mode) -> None:
        self.mode: Mode = mode
        self.routes: dict[KeyHash, list[KeyHash]] = {}

        info("node", f"Radon is starting up, active mode is {mode.name}.")
        info("node", f"Pk: {PUBLIC_KEY}")

    async def async_init(self) -> None:
        asyncio.create_task(self.start_socket())
        if self.mode == Mode.ROUTER:
            tasks: list[asyncio.Task] = [
                asyncio.create_task(self.mesh_with(address, public_key))
                for address, public_key in RADON_KNOWN_ROUTERS
            ]
            info("router", "All outgoing meshes have been initialized!")

            # Halt event loop
            await asyncio.gather(*tasks)
            return

        for address, public_key in RADON_KNOWN_ROUTERS:
            await self.mesh_with(address, public_key)

    async def process_packet(self, ptype: PacketType, payload: dict[str, typing.Any]) -> None:
        print(ptype, payload)

    async def mesh_with(self, address: str, public_key: str) -> None:
        if public_key == PUBLIC_KEY:
            return info("mesh", f"Skipping {address}, because that's us")

        info("mesh", f"Attempting to mesh with {address}")

        socket = None
        while socket is None:
            try:
                socket = await connect(f"ws://{address}:26104")

            except ConnectionError:
                await asyncio.sleep(5)

        await socket.send(build_packet(PacketType.AUTH, {"publicKey": PUBLIC_KEY}))
        while socket.state == State.OPEN:
            message = extract_packet(str(await socket.recv()))
            if message is None:
                break

            await self.process_packet(*message)

        await socket.close()

    async def start_socket(self) -> None:
        async with serve(self.process_client, "0.0.0.0", 26104) as socket:
            info("node", "Socket created and listening at http://127.0.0.1:26104")
            await socket.serve_forever()

    async def process_client(self, client: ServerConnection) -> None:
        try:
            async for message in client:
                message = extract_packet(str(message))
                if message is None:
                    break

                await self.process_packet(*message)

        except WebSocketException:
            info("router", "Websocket exception occured! Client has been killed.")

        await client.close()

# Handle main
if __name__ == "__main__":
    a = ArgumentParser()
    a.add_argument("-t", "--type", choices = ("node", "router"), required = True)

    # Startup node
    node: RadonNode = RadonNode(Mode[a.parse_args().type.upper()])
    asyncio.run(node.async_init())

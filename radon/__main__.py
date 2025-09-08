# Copyright (c) 2025 iiPython

# Modules
import os
import asyncio
from enum import Enum
from dataclasses import dataclass
from argparse import ArgumentParser

from websockets import State
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve

from nacl.exceptions import CryptoError

from radon import RADON_KNOWN_ROUTERS
from radon.comms import PUBLIC_KEY, decrypt, encrypt
from radon.utils.logs import error, info
from radon.utils.encoding import (
    encode, decode,
    build_packet, extract_packet, PacketType
)

# Initialization
class Mode(Enum):
    NODE   = 1
    ROUTER = 2

@dataclass
class NodeInformation:

    root: str | None
    """The respective root of this node, None signifies the node is connected to us."""

class RadonNode:
    def __init__(self, mode: Mode) -> None:
        self.mode: Mode = mode

        self.nodemap: dict[str, NodeInformation]
        self.routers: dict[str, ServerConnection]

        info("node", f"Radon is starting up, active mode is {mode.name}.")
        info("node", f"Pk: {PUBLIC_KEY}")

    async def async_init(self) -> None:
        if self.mode == Mode.ROUTER:
            asyncio.create_task(self.start_socket())

            tasks: list[asyncio.Task] = [
                asyncio.create_task(self.mesh_with(address, decode(public_key)))
                for address, public_key in RADON_KNOWN_ROUTERS
            ]
            info("node", "Radon initialized!")

            # Halt event loop
            await asyncio.gather(*tasks)

        if self.mode == Mode.NODE:
            for address, public_key in RADON_KNOWN_ROUTERS:
                await self.mesh_with(address, decode(public_key))

    async def mesh_with(self, address: str, public_key: bytes) -> None:
        if public_key == decode(PUBLIC_KEY):
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

            match message:
                case (PacketType.AUTH, {"challenge": challenge_text}):
                    try:
                        decrypted_challenge = decrypt(public_key, challenge_text)
                        await socket.send(build_packet(PacketType.AUTH, {"answer": encrypt(public_key, decrypted_challenge)}))

                    except CryptoError:
                        error("mesh", f"Failed to decrypt challenge from {address}, their keys might be invalid!")
                        break

                case (PacketType.ACK, {}):
                    info("mesh", f"Successfully meshed with {address}!")

                case _:
                    print("Unmatched packet:", message)

        await socket.close()

    async def start_socket(self) -> None:
        async with serve(self.process_client, "0.0.0.0", 26104) as socket:
            info("router", "Socket created and listening at http://127.0.0.1:26104")
            await socket.serve_forever()

    async def process_client(self, client: ServerConnection) -> None:

        # Authentication data
        answer: str | None = None
        known_pubkey: str | None = None

        # Handle client loop
        async for message in client:
            message = extract_packet(str(message))
            if message is None:
                break

            match message:
                case (PacketType.AUTH, {"publicKey": public_key}):
                    answer, known_pubkey = encode(os.urandom(32)), str(public_key)
                    await client.send(build_packet(PacketType.AUTH, {"challenge": encrypt(decode(known_pubkey), answer)}))

                case (PacketType.AUTH, {"answer": given_answer}) if known_pubkey is not None:
                    given_answer = decrypt(decode(known_pubkey), given_answer)
                    if given_answer != answer:
                        break

                    if known_pubkey in [x[1] for x in RADON_KNOWN_ROUTERS]:
                        info("mesh", f"New router connected! Pk: {known_pubkey}")
                        self.routers[known_pubkey] = client

                    else:
                        info("mesh", f"New node connected! Pk: {known_pubkey}")

                        self.nodemap[known_pubkey] = NodeInformation(root = None)
                        for router in self.routers.values():
                            info("mesh", f"Advertised us as a route for {known_pubkey}")
                            await router.send(build_packet(PacketType.MESH, {"nodeId": known_pubkey}))

                    await client.send(build_packet(PacketType.ACK))

                case (PacketType.MESH, {"nodeId": node_pubkey}) if known_pubkey in self.routers:
                    info("mesh", f"{known_pubkey} has a new node: {node_pubkey}")
                    self.nodemap[node_pubkey] = NodeInformation(known_pubkey)

        await client.close()

# Handle main
if __name__ == "__main__":
    a = ArgumentParser()
    a.add_argument("-t", "--type", choices = ("node", "router"), required = True)

    # Startup node
    node: RadonNode = RadonNode(Mode[a.parse_args().type.upper()])
    asyncio.run(node.async_init())

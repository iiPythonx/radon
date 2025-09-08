# Copyright (c) 2025 iiPython

# Modules
import os
import asyncio
from enum import Enum
from argparse import ArgumentParser

from websockets import State
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve

from radon import RADON_KNOWN_ROUTERS
from radon.comms import PUBLIC_KEY, decrypt, encrypt
from radon.utils.logs import info
from radon.utils.encoding import (
    decode,
    build_packet,
    encode, extract_packet, PacketType
)

# Initialization
class Mode(Enum):
    NODE   = 1
    ROUTER = 2

class RadonNode:
    def __init__(self, mode: Mode) -> None:
        self.mode: Mode = mode

        info("node", f"Radon is starting up, active mode is {mode.name}.")
        info("node", f"Pk: {PUBLIC_KEY}")

    async def async_init(self) -> None:
        if self.mode == Mode.ROUTER:
            await asyncio.create_task(self.start_socket())

        info("node", "Radon initialized!")
        await asyncio.gather(*[
            asyncio.create_task(self.mesh_with(address, decode(public_key)))
            for address, public_key in RADON_KNOWN_ROUTERS
        ])

    async def mesh_with(self, address: str, public_key: bytes) -> None:
        info("mesh", f"Attempting to mesh with {address}")
        async with connect(f"ws://{address}:26104") as socket:
            await socket.send(build_packet(PacketType.AUTH, {"publicKey": PUBLIC_KEY}))
            while socket.state == State.OPEN:
                message = extract_packet(str(await socket.recv()))
                if message is None:
                    break

                match message:
                    case (PacketType.AUTH, {"challenge": challenge_text}):
                        decrypted_challenge = decrypt(public_key, challenge_text)
                        await socket.send(build_packet(PacketType.AUTH, {"answer": encrypt(public_key, decrypted_challenge)}))

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
        known_pubkey: bytes | None = None

        # Handle client loop
        async for message in client:
            message = extract_packet(str(message))
            if message is None:
                break

            match message:
                case (PacketType.AUTH, {"publicKey": public_key}):
                    answer, known_pubkey = encode(os.urandom(32)), decode(public_key)
                    await client.send(build_packet(PacketType.AUTH, {"challenge": encrypt(known_pubkey, answer)}))

                case (PacketType.AUTH, {"answer": given_answer}) if known_pubkey is not None:
                    given_answer = decrypt(known_pubkey, given_answer)
                    if given_answer != answer:
                        break

                    info("mesh", f"New node connected! Pk: {encode(known_pubkey)}")
                    await client.send(build_packet(PacketType.ACK))

        await client.close()

# Handle main
if __name__ == "__main__":
    a = ArgumentParser()
    a.add_argument("-t", "--type", choices = ("node", "router"), required = True)

    # Startup node
    node: RadonNode = RadonNode(Mode[a.parse_args().type.upper()])
    asyncio.run(node.async_init())

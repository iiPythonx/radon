# Copyright (c) 2025 iiPython

# Modules
import os
import asyncio
from enum import Enum
from dataclasses import dataclass
from argparse import ArgumentParser

from websockets import State, WebSocketException
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve

from nacl.exceptions import CryptoError

from radon import RADON_KNOWN_ROUTERS, KNOWN_ROUTER_KEYS
from radon.comms import PUBLIC_KEY, decrypt, encrypt
from radon.utils.logs import error, info, warn
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
    type: Mode
    """The type of the node connected to us."""

    socket: ServerConnection | None
    """The local socket for this node, if None then we don't handle the node."""

    root: str | None
    """The respective root of this node, None signifies the node is connected to us."""

class RadonNode:
    def __init__(self, mode: Mode) -> None:
        self.mode: Mode = mode

        self.nodemap: dict[str, NodeInformation] = {}

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

            # Handle routing logic
            match message:

                # Handle authentication (all ways)
                case (PacketType.AUTH, {"challenge": challenge_text}):
                    try:
                        decrypted_challenge = decrypt(decode(public_key), challenge_text)
                        await socket.send(build_packet(PacketType.AUTH, {"answer": encrypt(decode(public_key), decrypted_challenge)}))

                    except CryptoError:
                        error("mesh", f"Failed to decrypt challenge from {address}, their keys might be invalid!")
                        break

                case (PacketType.ACK, {}):
                    info("mesh", f"Successfully meshed with {address}!")

                    # Request the latest nodelist from the router
                    await socket.send(build_packet(PacketType.MESH, {}))

                # Handle router to router meshing
                case (PacketType.MESH, {"nodeId": node_pubkey}) if public_key in KNOWN_ROUTER_KEYS:
                    info("mesh", f"{public_key} has a new node: {node_pubkey}")
                    self.nodemap[node_pubkey] = NodeInformation(Mode.NODE, None, public_key)

                # Handle router -> node data pushing
                # This is also valid for router -> router transport
                case (PacketType.MESH, {"nodeList": received_nodelist}) if public_key in KNOWN_ROUTER_KEYS:
                    received_nodelist = {k: NodeInformation(Mode[v["type"]], None, v["root"]) for k, v in received_nodelist.items()}

                    self.nodemap |= received_nodelist
                    info("mesh", f"Appended {len(received_nodelist)} node(s) from {public_key}!")
                    print(self.nodemap)

                # Just here for the sake of logging
                case _:
                    warn("node", f"Packet was unhandled: {message}")

        await socket.close()

    async def start_socket(self) -> None:
        async with serve(self.process_client, "0.0.0.0", 26104) as socket:
            info("node", "Socket created and listening at http://127.0.0.1:26104")
            await socket.serve_forever()

    async def process_client(self, client: ServerConnection) -> None:

        # Authentication data
        answer: str | None = None
        known_pubkey: str | None = None

        # Handle client loop
        try:
            async for message in client:
                message = extract_packet(str(message))
                if message is None:
                    break

                match message:
                    case (PacketType.AUTH, {"publicKey": public_key}) if self.mode == Mode.ROUTER:
                        answer, known_pubkey = encode(os.urandom(32)), str(public_key)
                        await client.send(build_packet(PacketType.AUTH, {"challenge": encrypt(decode(known_pubkey), answer)}))

                    case (PacketType.AUTH, {"answer": given_answer}) if known_pubkey is not None and self.mode == Mode.ROUTER:
                        given_answer = decrypt(decode(known_pubkey), given_answer)
                        if given_answer != answer:
                            break

                        # Handle broadcasting of node information
                        if known_pubkey in KNOWN_ROUTER_KEYS:
                            info("mesh", f"New router connected! Pk: {known_pubkey}")
                            self.nodemap[known_pubkey] = NodeInformation(Mode.ROUTER, client, None)

                        else:
                            info("mesh", f"New node connected! Pk: {known_pubkey}")

                            self.nodemap[known_pubkey] = NodeInformation(Mode.NODE, client, None)
                            for node in self.nodemap.values():
                                if node.socket is None:
                                    continue

                                await node.socket.send(build_packet(PacketType.MESH, {"nodeId": known_pubkey}))

                            info("mesh", f"Advertised us as a route for {known_pubkey}")

                        # And acknowledge the authentication
                        await client.send(build_packet(PacketType.ACK))

                    # Handle sending existing nodelist
                    case (PacketType.MESH, {}):
                        await client.send(build_packet(PacketType.MESH, {
                            "nodeList": {
                                k: {"type": v.type, "root": v.root or PUBLIC_KEY}
                                for k, v in self.nodemap.items()
                            }
                        }))

        except WebSocketException:
            info("router", "Websocket exception occured! Client has been killed.")
            pass

        await client.close()

# Handle main
if __name__ == "__main__":
    a = ArgumentParser()
    a.add_argument("-t", "--type", choices = ("node", "router"), required = True)

    # Startup node
    node: RadonNode = RadonNode(Mode[a.parse_args().type.upper()])
    asyncio.run(node.async_init())

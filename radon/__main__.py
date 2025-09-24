# Copyright (c) 2025 iiPython

# Modules
import os
import typing
import asyncio
from enum import Enum
from argparse import ArgumentParser

from websockets import ClientConnection, State, WebSocketException
from websockets.asyncio.client import connect
from websockets.asyncio.server import ServerConnection, serve

from radon import RADON_KNOWN_ROUTERS
from radon.utils.encoding import (
    build_packet, decode, encode, extract_packet, PacketType
)

from radon.comms import decrypt, encrypt, fetch_keys
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
        self.routers: list[ClientConnection] = []

        log.info("node", f"Radon is starting up, active mode is {mode.name}.")
        log.info("node", f"\t-> Public: {self.public_key}")
        log.info("node", f"\t-> Which was loaded from: $RADONDIR/{pk_filename}")

    async def async_init(self) -> None:
        for public_key, (address, port) in RADON_KNOWN_ROUTERS.items():
            asyncio.create_task(self.mesh_with(address, port, public_key))

        await self.start_socket()

    async def process_packet(self, client: ServerConnection | ClientConnection, ptype: PacketType, payload: dict[str, typing.Any]) -> None:
        log.network(ptype.name, str(payload))
        match (ptype, payload):
            case (PacketType.ACK, {"success": True}) if encode(getattr(client, "pk")) in RADON_KNOWN_ROUTERS:
                await client.send(build_packet(PacketType.ROUTE_REQ))

            case (PacketType.ROUTE_REQ, {"routes": routes}) if encode(getattr(client, "pk")) in RADON_KNOWN_ROUTERS:
                self.routes |= routes
                log.info("mesh", "Merged route list from router!")

            case (PacketType.ROUTE_REQ, {}) if self.mode == Mode.ROUTER:
                await client.send(build_packet(PacketType.ROUTE_REQ, {"routes": self.routes}))

            case (PacketType.ROUTE_ADD, {"client": encoded_client, "router": router_public_key}) if encode(getattr(client, "pk")) in RADON_KNOWN_ROUTERS:
                if encoded_client not in self.routes:
                    self.routes[encoded_client] = []

                if router_public_key not in self.routes[encoded_client]:
                    self.routes[encoded_client].append(router_public_key)
                    log.info("mesh", f"{router_public_key} is a new route for {encoded_client}")

            case (PacketType.AUTH, {"publicKey": sent_public_key}):
                if self.mode == Mode.NODE:
                    return await client.send(build_packet(PacketType.ERROR, {"message": "API disabled."}))

                setattr(client, "pk", decode(sent_public_key))
                setattr(client, "ch", encode(os.urandom(32)))

                data = encrypt(self.private_key, decode(sent_public_key), getattr(client, "ch"))
                await client.send(build_packet(PacketType.AUTH, {"challenge": data}))

            case (PacketType.AUTH, {"encryptedResponse": encrypted_response}):
                if self.mode == Mode.NODE:
                    return await client.send(build_packet(PacketType.ERROR, {"message": "API disabled."}))

                decrypted_response = decrypt(self.private_key, getattr(client, "pk"), encrypted_response)
                challenge_correct = decrypted_response == getattr(client, "ch")
                if challenge_correct:
                    encoded_client = encode(getattr(client, "pk"))
                    if encoded_client not in self.routes:
                        self.routes[encoded_client] = []

                    self.routes[encoded_client].append(self.public_key)

                    log.info("mesh", "Propagating new route around the network")
                    for router in self.routers:
                        await router.send(build_packet(PacketType.ROUTE_ADD, {"client": encoded_client, "router": self.public_key}))
                        log.info("mesh", f"\t-> Propagated through {encode(getattr(router, 'pk'))}")

                    log.info("mesh", f"We are now a designated router for {encoded_client}")

                await client.send(build_packet(PacketType.ACK, {"success": challenge_correct}))

            case (PacketType.AUTH, {"challenge": challenge_text}):
                decrypted_challenge = decrypt(self.private_key, getattr(client, "pk"), challenge_text)
                encrypted_response = encrypt(self.private_key, getattr(client, "pk"), decrypted_challenge)
                await client.send(build_packet(PacketType.AUTH, {"encryptedResponse": encrypted_response}))

    async def mesh_with(self, address: str, port: int, public_key: str) -> None:
        if public_key == self.public_key:
            return log.info("mesh", f"Skipping {address}, because that's us")

        log.info("mesh", f"Attempting to mesh with {address}:{port}")

        socket, interval = None, 5
        while socket is None:
            try:
                socket = await connect(f"ws://{address}:{port}")
                setattr(socket, "pk", decode(public_key))

                self.routers.append(socket)

            except (ConnectionError, TimeoutError):
                await asyncio.sleep(interval)
                log.warn("mesh", f"Failed to mesh with {address}:{port}, trying again in {interval} seconds.")

                interval += 10

        await socket.send(build_packet(PacketType.AUTH, {"publicKey": self.public_key}))
        while socket.state == State.OPEN:
            message = extract_packet(str(await socket.recv()))
            if message is None:
                break

            await self.process_packet(socket, *message)

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

                await self.process_packet(client, *message)

        except WebSocketException:
            if hasattr(client, "pk") and self.mode == Mode.ROUTER:
                log.info("mesh", "Propagating removed route around the network")

                encoded_client = encode(getattr(client, "pk"))
                self.routes[encoded_client].remove(self.public_key)

                for router in self.routers:
                    await router.send(build_packet(PacketType.ROUTE_DEL, {"client": encoded_client, "router": self.public_key}))
                    log.info("mesh", f"\t-> Propagated through {encode(getattr(router, 'pk'))}")

                log.info("mesh", f"We are no longer routing {encoded_client}")

            log.info("router", "Websocket exception occured! Client has been killed.")

        await client.close()

# Handle main
if __name__ == "__main__":
    a = ArgumentParser()
    a.add_argument("-t", "--type", choices = ("node", "router"), required = True, help = "Type of node you want to launch, this should most likely be NODE.")
    a.add_argument("-p", "--port", type = int, default = 26104)
    a.add_argument("-k", "--keyname", type = str, default = "pk.bin", help = "The filename of the key you want to use/generate.")

    args = a.parse_args()

    # Startup node
    node: RadonNode = RadonNode(Mode[args.type.upper()], port = args.port, pk_filename = args.keyname)
    asyncio.run(node.async_init())

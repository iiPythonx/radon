# Copyright (c) 2025 iiPython

# Modules
import asyncio
from websockets.asyncio.client import connect

from rich import box
from rich.table import Table
from rich.console import Console

from radon.utils.encoding import PacketType, build_packet, extract_packet

# Initialization
async def main(address: str) -> None:
    socket, console = await connect(address), Console()
    while True:
        await socket.send(build_packet(PacketType.ROUTE_REQ))

        packet = extract_packet(str(await socket.recv()))
        if packet is None:
            break

        response_type, data, nonce = packet
        if response_type != PacketType.ROUTE_REQ:
            print("Protocol exception occured!")
            break

        # Generate table
        table = Table(title = "Radon - Active Known Routes", show_lines = True, box = box.ROUNDED)

        table.add_column("Node", style = "cyan")
        table.add_column("Router(s)", style = "magenta")
        table.add_column("Source", style = "red")
        for target, routers in data["routes"].items():
            table.add_row(target, "\n".join(routers), address)

        console.clear()
        console.print(table)

        await asyncio.sleep(5)

asyncio.run(main("ws://127.0.0.1:26104"))


# Copyright (c) 2025-2026 iiPython

import argparse
import asyncio
from urllib.parse import urlsplit

from radon import Client
from radon.utils.logs import log
from radon.frame import FRAME_MAP, Frame, ParamValue, ResponseFrame

def infer_param_type(param: str) -> ParamValue:
    if param.lower() in {"true", "false"}:
        return param.lower() == "true"

    try:
        return int(param)

    except ValueError:
        return param

def parse_url(url: str) -> tuple[str, int, str, dict[str, ParamValue]]:
    target = urlsplit(url)
    if target.scheme != "radon":
        raise ValueError("Specified URL is not using the Radon protocol!")

    if not target.hostname:
        raise ValueError("No hostname provided in given URL!")

    # Parse query options into radon parameters
    params: dict[str, ParamValue] = {}
    if target.query:
        for query in target.query.split("&"):
            if "=" not in query:
                raise ValueError(f"Error in query '{query}': no value associated with key")

            key, value = query.split("=")
            params[key] = infer_param_type(value)

    return (
        target.hostname,
        target.port or 7777,
        target.path,
        params
    )

async def send_frame(frame_type: str, url: str, binary: bool, verbose: bool) -> None:
    host, port, path, params = parse_url(url)
    if frame_type != "retrieve" and (path or params):
        log.warn("frame", f"Path and or params were provided, but this frame type ({frame_type.upper()}) don't support them")

    client = Client()
    if verbose:
        log.network("tx", f"Connecting to {host} on port {port}")

    await client.connect(host, port)

    # Send off frame
    frame: Frame | None = None
    match frame_type:
        case "retrieve":
            frame = await client.retrieve(path or "/", params)

        case "fuckoff":
            frame = await client.fuckoff()

        case _:
            log.error("frame", f"No matching frame type for {frame_type.upper()} was found!")

    if frame is None:
        return

    # Verbose logging
    frame_name = FRAME_MAP[frame.packet_type].__name__
    if verbose:
        log.network("rx", f"Protocol version: {'.'.join(str(_) for _ in frame.version)}")
        log.network("rx", f"Frame type: 0x{frame.packet_type:02x} ({frame_name})")
        log.network("rx", f"Packet flags: {frame.flags:08b}")
        log.network("rx", f"Packet ID: {frame.packet_id}")

    # Show data
    if isinstance(frame, ResponseFrame):
        if verbose:
            log.info(frame_name, "Begin response parameter list")
            for key, value in frame.params.items():
                log.info(frame_name, f"{key}: {value} ({type(value).__name__})")

        return print(str(frame.body)[2:-1] if binary else frame.body.decode("utf-8"))

    log.info("data", "Frame was received, but no data is present (ie, non-response frame received).")

if __name__ == "__main__":
    p = argparse.ArgumentParser(
        prog = "rx",
        description = "a cli client for the radon protocol",
        epilog = "https://github.com/iiPythonx/radon"
    )

    # Parameters
    p.add_argument("url")
    p.add_argument("-t", "--type", required = True)
    p.add_argument("-b", "--binary", action = "store_true")
    p.add_argument("-v", "--verbose", action = "store_true")

    args = p.parse_args()

    # Make request
    asyncio.run(send_frame(args.type.lower(), args.url, args.binary, args.verbose))

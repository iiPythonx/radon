# Copyright (c) 2026 iiPython

import socket
import struct

from radon.frame import FRAME_MAP, RADON_MAGIC, Frame, ParamValue, RetrieveFrame

class Client:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def read(self) -> Frame | None:

        # Read frame
        if self.socket.recv(4) != RADON_MAGIC:
            raise ValueError("We've received something that isn't a Radon frame!")

        version_major, version_minor, packet_type, packet_flags = \
            [int(byte) for byte in self.socket.recv(4)]

        packet_id = struct.unpack(">Q", self.socket.recv(8))[0]
        payload_size = struct.unpack(">I", self.socket.recv(4))[0]

        packet = {
            "version_major": version_major,
            "version_minor": version_minor,
            "packet_flags": packet_flags,
            "packet_id": packet_id
        }
        payload = memoryview(self.socket.recv(payload_size))

        # Build frame
        frame = FRAME_MAP.get(packet_type)
        return frame.from_payload(payload, **packet) if frame is not None else None

    def connect(self, host: str, port: int = 7777) -> None:
        self.socket.connect((host, port))

    def retrieve(self, path: str, params: dict[str, ParamValue] = {}, body: bytes = b"") -> Frame | None:
        self.socket.sendall(RetrieveFrame(path, params, body).build())
        return self.read()

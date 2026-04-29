import asyncio
import typing
import traceback
from queue import Queue

import mpv

from radon import Client
from radon.frame import ResponseFrame

client = Client()

async def main() -> None:
    await client.connect("localhost")

    # Read stream metadata
    filename = input("Filename to stream: ")
    response = await client.retrieve("/stream", {"file": filename})
    if not isinstance(response, ResponseFrame):
        raise RuntimeError("Radon protocol failed!")

    filesize = response.params["size"]
    if not isinstance(filesize, int):
        raise ValueError("Server returned an invalid filesize!")

    # Begin streaming
    chunk_size, chunk_queue = 5 * (1024 ** 2), Queue(maxsize = 1)

    async def stream_chunks() -> None:
        try:
            for offset in range(0, filesize, chunk_size):
                chunk = await client.retrieve(
                    "/stream", 
                    {"file": filename, "range_start": offset, "range_rsize": chunk_size}
                )
                
                if not isinstance(chunk, ResponseFrame):
                    raise RuntimeError("Chunk decoding failed!")

                await asyncio.to_thread(chunk_queue.put, chunk.body)
                
        except Exception:
            traceback.print_exc()

        await asyncio.to_thread(chunk_queue.put, None)

    stream_task = asyncio.create_task(stream_chunks())

    # Setup MPV instance
    player = mpv.MPV(
        input_default_bindings = True,
        input_vo_keyboard = True,
        osc = True
    )

    @player.python_stream("radon")
    def stream_from_radon() -> typing.Generator:
        while True:
            chunk = chunk_queue.get()
            if chunk is None:
                break

            yield chunk

    player.play("python://radon")

    await asyncio.to_thread(player.wait_for_playback)
    stream_task.cancel()

    await stream_task

    # Close the connection
    await client.fuckoff()

if __name__ == "__main__":
    asyncio.run(main())

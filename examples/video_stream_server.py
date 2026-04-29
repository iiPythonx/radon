import asyncio
import typing
import json
from pathlib import Path

from radon import Service, RetrieveFrame
from radon.frame import ResponseFrame

def dump(data: typing.Any) -> bytes:
    return json.dumps(data).encode("utf-8")

service = Service()

@service.bind(RetrieveFrame, "/stream")
async def route_index(frame: RetrieveFrame) -> ResponseFrame:
    if "file" not in frame.params:
        return ResponseFrame({"success": False}, dump({"message": "No file parameter was provided."}))

    file = Path(str(frame.params["file"]))
    if not file.is_file():
        return ResponseFrame({"success": False}, dump({"message": "Specified file does not exist."}))

    # Check for range data
    range_start = frame.params.get("range_start")
    range_rsize = frame.params.get("range_rsize")

    if range_start is not None and range_rsize is not None:
        if not (isinstance(range_start, int) and isinstance(range_rsize, int)):
            return ResponseFrame({"success": False}, dump({"message": "Provided range values are not valid integers."}))

        with file.open("rb") as handle:
            handle.seek(range_start)
            return ResponseFrame({"success": True}, handle.read(range_rsize))

    file_size = file.stat().st_size
    return ResponseFrame({"success": True, "size": file_size})

if __name__ == "__main__":
    asyncio.run(service.serve("localhost", 7777))

import asyncio
import struct


class AsyncLengthPrefixedSocket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer

    async def send(self, payload: bytes) -> None:
        header = struct.pack(">I", len(payload))
        self.writer.write(header + payload)
        await self.writer.drain()

    async def read_next(self) -> bytes:
        header = await self.reader.readexactly(4)
        length = struct.unpack(">I", header)[0]
        payload = await self.reader.readexactly(length)
        return payload

    async def close(self) -> None:
        self.writer.close()
        await self.writer.wait_closed()

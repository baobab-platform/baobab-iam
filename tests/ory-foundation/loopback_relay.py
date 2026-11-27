"""Fixed runner-loopback listeners for the isolated Ory Foundation bridge."""

import asyncio
from contextlib import AsyncExitStack

ENDPOINTS = {
    4433: "172.30.146.2",
    4434: "172.30.146.2",
    4444: "172.30.146.3",
    4445: "172.30.146.3",
}


async def copy_stream(reader, writer):
    while data := await reader.read(65536):
        writer.write(data)
        await writer.drain()
    writer.write_eof()


async def relay(reader, writer, destination, port):
    upstream_writer = None
    try:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(destination, port), timeout=3,
        )
        async with asyncio.TaskGroup() as tasks:
            tasks.create_task(copy_stream(reader, upstream_writer))
            tasks.create_task(copy_stream(upstream_reader, writer))
    except (OSError, TimeoutError, ExceptionGroup):
        # The readiness checks report transport failure without logging traffic.
        pass
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
        writer.close()


async def main():
    async with AsyncExitStack() as servers:
        for port, destination in ENDPOINTS.items():
            async def handler(reader, writer, host=destination, target=port):
                await relay(reader, writer, host, target)
            server = await asyncio.start_server(handler, "127.0.0.1", port)
            await servers.enter_async_context(server)
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())

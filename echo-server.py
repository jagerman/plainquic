#!/usr/bin/python3

import asyncio

async def handle_echo(reader, writer):
    while True:
        data = await reader.read(1024)
        if not data:
            break

        message = data  #.decode()
        addr = writer.get_extra_info('peername')

        print(f"Received {message!r} from {addr!r}")

        print(f"Send: {message!r}")
        writer.write(data)
    await writer.drain()

    print("Close the connection")
    writer.close()

async def main():
    server = await asyncio.start_server(handle_echo, '127.0.0.1', 4444)

    addr = server.sockets[0].getsockname()
    print(f'Serving on {addr}')

    async with server:
        await server.serve_forever()

asyncio.run(main())

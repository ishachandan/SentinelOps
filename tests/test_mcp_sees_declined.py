import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def test():
    server_params = StdioServerParameters(command='python', args=['server.py'])
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool('execute_pending_action', {'token': 'decline_test_999'})
            print("MCP execute result:", result.content[0].text)

asyncio.run(test())

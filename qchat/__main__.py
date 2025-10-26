from .cli import cli
import asyncio, uvloop
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

if __name__=='__main__': cli()

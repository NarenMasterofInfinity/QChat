import asyncio, secrets
from typing import Dict
from .transport.message import pack, unpack
from .util_log import log

class Conn:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, name: str = "client"):
        self.reader=reader; self.writer=writer; self.name=name
        self.waiters: Dict[str, asyncio.Future] = {}; self.push_queue: asyncio.Queue = asyncio.Queue()
        self._reader_task = None
    async def start_reader(self):
        async def _loop():
            try:
                while True:
                    szb = await self.reader.readexactly(4); sz = int.from_bytes(szb,'big')
                    payload = await self.reader.readexactly(sz); msg = unpack(payload); rid = msg.get('rid')
                    log(f"{self.name}/recv:", msg.get('type'), "rid", rid)
                    if rid and rid in self.waiters: self.waiters[rid].set_result(msg); del self.waiters[rid]
                    else: await self.push_queue.put(msg)
            except Exception as e:
                log(f"{self.name}/reader-exit:", e)
                for rid,f in list(self.waiters.items()):
                    if not f.done(): f.set_exception(RuntimeError('connection closed'))
                self.waiters.clear()
        self._reader_task = asyncio.create_task(_loop())
    async def request(self, obj: dict, timeout: float = 10.0) -> dict:
        rid = secrets.token_hex(8); obj = dict(obj); obj['rid'] = rid
        fut = asyncio.get_event_loop().create_future(); self.waiters[rid] = fut
        data = pack(obj); self.writer.write(len(data).to_bytes(4,'big')+data)
        log(f"{self.name}/send:", obj.get('type'), "rid", rid)
        await self.writer.drain()
        return await asyncio.wait_for(fut, timeout=timeout)
    async def close(self):
        try: self.writer.close()
        except Exception: pass
        if self._reader_task: self._reader_task.cancel()


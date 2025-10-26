import asyncio, click, base64
from .server import HubServer
from .conn import Conn
from .transport.quic_transport import open_quic_connection, quic_shutdown
from .util_log import log

@click.group()
def cli(): ...

@cli.command('start-server')
@click.option('--host', default='0.0.0.0')
@click.option('--port', default=8443, type=int)
@click.option('--quic', is_flag=True)
def start_server(host, port, quic):
    async def main():
        s=HubServer(host, port, use_quic=quic); await s.start(); await asyncio.Future()
    try: asyncio.run(main())
    except KeyboardInterrupt: pass

@cli.command('interactive')
@click.option('--host', default='127.0.0.1')
@click.option('--port', default=8443, type=int)
@click.option('--quic', is_flag=True)
def interactive(host, port, quic):
    async def _open():
        if quic: 
            log("cli: opening QUIC")
            return await open_quic_connection(host, port)
        else:
            log("cli: opening TCP")
            return await asyncio.open_connection(host, port)
    async def main():
        reader,writer=await _open(); c=Conn(reader,writer, name="cli"); await c.start_reader()
        try:
            while True:
                click.echo('\n1) Register 2) Login 3) Create 4) Join 5) Approve 6) List 7) Exit')
                ch=click.prompt('Choice', type=int, default=7)
                if ch==1:
                    u=click.prompt('User'); p=click.prompt('Pass', hide_input=True)
                    print(await c.request({'type':'register','user':u,'password':p,
                                           'sig_pk_b64':base64.b64encode(b'x').decode(),
                                           'kem_pk_b64':base64.b64encode(b'y').decode()}))
                elif ch==2:
                    u=click.prompt('User'); p=click.prompt('Pass', hide_input=True); print(await c.request({'type':'login','user':u,'password':p}))
                elif ch==3:
                    g=click.prompt('Group'); u=click.prompt('Admin'); print(await c.request({'type':'create_group','group':g,'user':u}))
                elif ch==4:
                    g=click.prompt('Group'); u=click.prompt('User'); print(await c.request({'type':'join_group','group':g,'user':u}))
                elif ch==5:
                    g=click.prompt('Group'); admin=click.prompt('Admin'); mem=click.prompt('Member')
                    try: _=await c.request({'type':'approve_member','group':g,'user':admin,'member':mem}, timeout=1.5); print('approve ok')
                    except Exception: print('approve sent (no immediate reply)')
                elif ch==6:
                    print(await c.request({'type':'list_groups'}))
                else:
                    break
        finally:
            await c.close()
            if quic: await quic_shutdown()
    asyncio.run(main())


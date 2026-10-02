"""Local capture server: TLS-over-TCP (h2 / http1.1) + QUIC (h3, via aioquic).

Records every ClientHello (raw bytes, parsed) and every HTTP request's frame-level details
into an in-memory Recorder. Connections are closed right after the first response (GOAWAY)
so the next navigation opens a new connection and exercises TLS session resumption.
"""
import asyncio, json, socket, ssl, struct, threading, time, traceback, itertools
import fp

class Recorder:
    def __init__(self):
        self.lock = threading.Lock(); self.events = []; self._ids = itertools.count(1)
    def next_id(self): return next(self._ids)
    def add(self, ev):
        ev.setdefault("ts", time.time())
        with self.lock: self.events.append(ev)
        return ev
    def snapshot(self, since=0):
        with self.lock: return list(self.events[since:])
    def mark(self):
        with self.lock: return len(self.events)

H2_FRAME = {0: "DATA", 1: "HEADERS", 2: "PRIORITY", 3: "RST_STREAM", 4: "SETTINGS", 5: "PUSH_PROMISE",
            6: "PING", 7: "GOAWAY", 8: "WINDOW_UPDATE", 9: "CONTINUATION"}
BODY = b"<!doctype html><html><head><link rel=icon href='data:,'><title>capture</title></head><body>ok</body></html>"

def _frame(ftype, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack(">I", sid) + payload

def _recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        d = s.recv(n - len(buf))
        if not d: raise EOFError
        buf += d
    return buf

class TCPServer:
    def __init__(self, rec, port, certfile, keyfile, host="127.0.0.1"):
        self.rec, self.port = rec, port
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(certfile, keyfile)
        self.ctx.set_alpn_protocols(["h2", "http/1.1"])
        self.sock = socket.socket(); self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port)); self.sock.listen(64)
    def start(self):
        threading.Thread(target=self._accept, daemon=True).start()
    def _accept(self):
        while True:
            c, a = self.sock.accept()
            threading.Thread(target=self._handle, args=(c, a), daemon=True).start()

    def _peek_ch(self, c):
        deadline = time.time() + 5
        while time.time() < deadline:
            data = c.recv(65536, socket.MSG_PEEK)
            if not data: return None
            msg = fp.extract_from_tls_records(data)
            if msg is not None: return msg
            time.sleep(0.02)
        return None

    def _handle(self, c, addr):
        cid = self.rec.next_id()
        try:
            c.settimeout(8)
            msg = self._peek_ch(c)
            if msg is None: return
            ch = fp.parse_client_hello(msg)
            self.rec.add({"kind": "clienthello", "transport": "tcp", "conn": cid, "port": addr[1],
                          "raw_hex": msg.hex(), "summary": fp.summarize(ch, "t")})
            try:
                t = self.ctx.wrap_socket(c, server_side=True)
            except Exception as e:
                self.rec.add({"kind": "tls_error", "conn": cid, "error": str(e)}); return
            alpn = t.selected_alpn_protocol()
            self.rec.add({"kind": "tls_done", "conn": cid, "alpn": alpn, "version": t.version(),
                          "resumed": t.session_reused})
            t.settimeout(4)
            if alpn == "h2": self._h2(t, cid)
            else: self._h1(t, cid)
        except (EOFError, socket.timeout, ConnectionError, ssl.SSLError):
            pass
        except Exception:
            self.rec.add({"kind": "server_error", "conn": cid, "error": traceback.format_exc()})
        finally:
            try: c.close()
            except Exception: pass

    def _h1(self, t, cid):
        buf = b""
        while b"\r\n\r\n" not in buf:
            d = t.recv(4096)
            if not d: return
            buf += d
        head = buf.split(b"\r\n\r\n")[0].decode("latin1").split("\r\n")
        method, path, _ = head[0].split(" ", 2)
        headers = [tuple(h.split(":", 1)) for h in head[1:] if ":" in h]
        self.rec.add({"kind": "request", "proto": "http/1.1", "conn": cid, "path": path, "method": method,
                      "headers": [[k, v.strip()] for k, v in headers]})
        t.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-store\r\nConnection: close\r\nContent-Length: %d\r\n\r\n" % len(BODY) + BODY)

    def _h2(self, t, cid):
        import hpack
        dec, enc = hpack.Decoder(), hpack.Encoder()
        if _recv_exact(t, 24) != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n": return
        t.sendall(_frame(4, 0, 0, b""))
        frames, settings, wu, prio, hdr_prio = [], None, None, [], None
        block, block_sid = b"", None
        while True:
            h = _recv_exact(t, 9)
            ln = int.from_bytes(h[:3], "big"); ftype, flags = h[3], h[4]
            sid = struct.unpack(">I", h[5:9])[0] & 0x7FFFFFFF
            p = _recv_exact(t, ln) if ln else b""
            fr = {"type": H2_FRAME.get(ftype, str(ftype)), "flags": flags, "stream": sid, "len": ln}
            if ftype == 4 and not (flags & 1):
                s = [list(struct.unpack(">HI", p[i:i+6])) for i in range(0, len(p), 6)]
                fr["settings"] = s
                if settings is None: settings = s
                t.sendall(_frame(4, 1, 0))
            elif ftype == 8:
                inc = struct.unpack(">I", p)[0] & 0x7FFFFFFF; fr["increment"] = inc
                if sid == 0 and wu is None: wu = inc
            elif ftype == 2:
                dep = struct.unpack(">I", p[:4])[0]
                fr["priority"] = {"exclusive": dep >> 31, "depends_on": dep & 0x7FFFFFFF, "weight": p[4] + 1}
                prio.append("%d:%d:%d:%d" % (sid, dep >> 31, dep & 0x7FFFFFFF, p[4] + 1))
            elif ftype == 6 and not (flags & 1):
                t.sendall(_frame(6, 1, 0, p))
            elif ftype in (1, 9):
                q = p
                if ftype == 1:
                    pad = 0
                    if flags & 0x8: pad = q[0]; q = q[1:]
                    if flags & 0x20:
                        dep = struct.unpack(">I", q[:4])[0]
                        hp = {"exclusive": dep >> 31, "depends_on": dep & 0x7FFFFFFF, "weight": q[4] + 1}
                        fr["priority"] = hp
                        if hdr_prio is None: hdr_prio = hp
                        q = q[5:]
                    if pad: q = q[:-pad]
                    block_sid = sid
                block += q
                if flags & 0x4:
                    hdrs = [[k if isinstance(k, str) else k.decode(), v if isinstance(v, str) else v.decode()]
                            for k, v in dec.decode(block)]
                    block = b""
                    path = next((v for k, v in hdrs if k == ":path"), None)
                    frames.append(fr)
                    self.rec.add({"kind": "request", "proto": "h2", "conn": cid, "stream": block_sid, "path": path,
                                  "headers": hdrs, "settings": settings, "window_update": wu,
                                  "priority_frames": prio, "headers_priority": hdr_prio, "frames": frames[:40]})
                    rh = enc.encode([(":status", "200"), ("content-type", "text/html"), ("cache-control", "no-store")])
                    t.sendall(_frame(1, 0x4, block_sid, rh) + _frame(0, 0x1, block_sid, BODY)
                              + _frame(7, 0, 0, struct.pack(">II", block_sid, 0)))
                    time.sleep(0.3)
                    return
            frames.append(fr)

# ---------------- QUIC / HTTP3 ----------------
class QUICServer:
    """aioquic-based h3 server in its own thread/event loop; hooks the TLS layer to grab the raw ClientHello."""
    def __init__(self, rec, port, certfile, keyfile, host="127.0.0.1"):
        self.rec, self.port, self.host, self.cert, self.key = rec, port, host, certfile, keyfile
        self.error = None; self.ready = threading.Event()
    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(10)
    def _run(self):
        try:
            asyncio.run(self._main())
        except Exception:
            self.error = traceback.format_exc(); self.ready.set()
    async def _main(self):
        from aioquic import tls as qtls
        from aioquic.asyncio import serve, QuicConnectionProtocol
        from aioquic.quic.configuration import QuicConfiguration
        from aioquic.quic.events import ProtocolNegotiated, ConnectionTerminated
        from aioquic.h3.connection import H3_ALPN, H3Connection
        from aioquic.h3.events import HeadersReceived
        rec = self.rec
        orig = qtls.Context._server_handle_hello
        def hooked(ctx, input_buf, *a, **k):
            try:
                msg = bytes(input_buf.data_slice(0, input_buf.capacity))
                ch = fp.parse_client_hello(msg)
                rec.add({"kind": "clienthello", "transport": "quic", "conn": rec.next_id(),
                         "raw_hex": msg.hex(), "summary": fp.summarize(ch, "q")})
            except Exception:
                rec.add({"kind": "server_error", "error": traceback.format_exc()})
            return orig(ctx, input_buf, *a, **k)
        qtls.Context._server_handle_hello = hooked
        tickets = {}
        class Proto(QuicConnectionProtocol):
            def __init__(s, *a, **k):
                super().__init__(*a, **k); s.h3 = None; s.cid = rec.next_id()
            def quic_event_received(s, ev):
                if isinstance(ev, ProtocolNegotiated):
                    rec.add({"kind": "quic_alpn", "conn": s.cid, "alpn": ev.alpn_protocol,
                             "resumed": getattr(ev, "session_resumed", None)})
                    if ev.alpn_protocol in H3_ALPN: s.h3 = H3Connection(s._quic)
                if s.h3 is None: return
                for e in s.h3.handle_event(ev):
                    if isinstance(e, HeadersReceived):
                        hdrs = [[k.decode(), v.decode()] for k, v in e.headers]
                        path = next((v for k, v in hdrs if k == ":path"), None)
                        rec.add({"kind": "request", "proto": "h3", "conn": s.cid, "stream": e.stream_id, "path": path,
                                 "headers": hdrs,
                                 "h3_settings": {str(k): v for k, v in (s.h3.received_settings or {}).items()} or None})
                        s.h3.send_headers(e.stream_id, [(b":status", b"200"), (b"content-type", b"text/html"),
                                                        (b"cache-control", b"no-store")])
                        s.h3.send_data(e.stream_id, BODY, end_stream=True)
                        s.transmit()
                        asyncio.get_event_loop().call_later(0.5, s._close)
            def _close(s):
                try:
                    if s.h3 is not None and s.h3.received_settings:
                        rec.add({"kind": "h3_settings", "conn": s.cid,
                                 "h3_settings": {str(k): v for k, v in s.h3.received_settings.items()}})
                    s._quic.close(); s.transmit()
                except Exception: pass
        cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN, max_datagram_frame_size=65536)
        cfg.load_cert_chain(self.cert, self.key)
        await serve(self.host, self.port, configuration=cfg, create_protocol=Proto,
                    session_ticket_fetcher=lambda label: tickets.pop(label, None),
                    session_ticket_handler=lambda t: tickets.__setitem__(t.ticket, t))
        self.ready.set()
        await asyncio.Future()

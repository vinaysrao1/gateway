"""Trusted deterministic HTTPS upstream. Never ships in the gateway runtime."""
import http.server, json, ssl, threading, time

class Fixture:
    def __init__(self, cert, key):
        self.requests=[]; self.total_calls=0;self.lock=threading.Lock();self.mode="normal";self.opened=threading.Event();self.closed=threading.Event()
        outer=self
        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version="HTTP/1.1"
            def log_message(self,*args): pass
            def do_GET(self):
                with outer.lock:outer.requests.append({"path":self.path,"headers":dict(self.headers)});outer.total_calls+=1
                body=b"APPROVED_FETCH_OK";self.send_response(200);self.send_header("Content-Type","text/plain");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)
            def do_POST(self):
                body=json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                with outer.lock:outer.requests.append({"path":self.path,"headers":dict(self.headers),"body":body});outer.total_calls+=1
                self.send_response(200);self.send_header("Content-Type","text/event-stream");self.send_header("Connection","close")
                if outer.mode in ("bad-length","bad-length-cr"):self.send_header("Content-Length","8192")
                if outer.mode=="bad-chunk":self.send_header("Transfer-Encoding","chunked")
                self.end_headers();self.close_connection=True
                def write(data):
                    if outer.mode=="bad-chunk":data=(hex(len(data))[2:]+"\r\n").encode()+data+b"\r\n"
                    self.wfile.write(data);self.wfile.flush()
                def emit(delta,finish=None):
                    data={"id":"fixture-chat","object":"chat.completion.chunk","created":1,"model":"gateway-fixture","choices":[{"index":0,"delta":delta,"finish_reason":finish}]}
                    write(("data: "+json.dumps(data)+"\n\n").encode())
                try:
                    if outer.mode=="stall":
                        emit({"role":"assistant","content":"started"});outer.opened.set()
                        while True: emit({"content":"."});time.sleep(.05)
                    if outer.mode=="truncate":emit({"role":"assistant","content":"partial"});return
                    if outer.mode in ("bad-length","bad-length-cr","bad-chunk"):
                        emit({"role":"assistant","content":"premature"});emit({},"stop")
                        write(b"data: [DONE]\r\r"if outer.mode=="bad-length-cr"else b"data: [DONE]\n\n");return
                    tool_results=[m for m in body["messages"] if m["role"]=="tool"]
                    if len(tool_results)==0:
                        emit({"role":"assistant","tool_calls":[{"index":0,"id":"fetch-call","type":"function","function":{"name":"gateway_fetch","arguments":'{"resource_id":"approved"}'}}]});emit({},"tool_calls")
                    elif len(tool_results)==1:
                        emit({"role":"assistant","tool_calls":[{"index":0,"id":"bash-call","type":"function","function":{"name":"bash","arguments":'{"command":"node /opt/pi/bypass-probe.mjs"}'}}]});emit({},"tool_calls")
                    else:emit({"role":"assistant","content":"GATEWAY_E2E_OK"});emit({},"stop")
                    write(b"data: [DONE]\n\n")
                except (BrokenPipeError,ConnectionResetError,ssl.SSLError):outer.closed.set()
        self.server=http.server.ThreadingHTTPServer(("11.0.0.2",443),Handler)
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key);self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        threading.Thread(target=self.server.serve_forever,daemon=True).start()
    def reset(self,mode):
        with self.lock:self.requests=[]
        self.mode=mode;self.opened.clear();self.closed.clear()
    def close(self):self.server.shutdown();self.server.server_close()

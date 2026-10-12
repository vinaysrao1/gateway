"""Linux-only acceptance. It fails, rather than skips, missing OS facilities."""
import json, os, pathlib, shutil, signal, socket, subprocess, tempfile, time
from fixture import Fixture

ROOT=pathlib.Path(tempfile.mkdtemp(prefix="gateway-acceptance-"))
cgroup_root=pathlib.Path("/sys/fs/cgroup")/ROOT.name
pathlib.Path("/sys/fs/cgroup/cgroup.subtree_control").write_text("+cpu +memory +pids")
cgroup_root.mkdir()
baseline_groups=set()
FIXTURES=pathlib.Path("/fixtures")
RUNTIME=pathlib.Path("/runtime")

def command(*args,**kwargs):return subprocess.run(args,check=True,text=True,**kwargs)
command("ip","link","add","fixture0","type","dummy")
command("ip","addr","add","11.0.0.2/32","dev","fixture0")
command("ip","link","set","fixture0","up")
with open("/etc/hosts","a")as f:f.write("\n11.0.0.2 fixture.gateway.test\n")
command("openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(ROOT/"key.pem"),"-out",str(ROOT/"cert.pem"),"-days","1","-subj","/CN=fixture.gateway.test","-addext","subjectAltName=DNS:fixture.gateway.test",stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
shutil.copy("/gateway",RUNTIME/"gateway")
shutil.copy("/bin/bash",RUNTIME/"usr/bin/bash")
shutil.copy("/usr/bin/curl",RUNTIME/"usr/bin/curl")
command("gcc","-O2","-o",str(RUNTIME/"usr/bin/raw-probe"),"/security/testdata/raw-probe.c")
(RUNTIME/"home/agent").mkdir(parents=True,exist_ok=True)
(RUNTIME/"run/gateway.sock").touch()
(RUNTIME/"pi-config").mkdir(exist_ok=True)
for file in ("models.json","settings.json"):shutil.copy(FIXTURES/file,RUNTIME/"pi-config"/file)
for file in ("gateway-extension.ts","bypass-probe.mjs"):shutil.copy(FIXTURES/file,RUNTIME/"opt/pi"/file)
secrets=ROOT/"secrets.json";secrets.write_text('{"model-key":"gateway-secret-canary"}');secrets.chmod(0o600)
policy=json.loads(pathlib.Path("/examples/policy.json").read_text())
policy["model_routes"][0]["upstream_url"]="https://fixture.gateway.test/v1/chat/completions"
policy["model_routes"][0]["allowed_models"]=["gateway-fixture"]
policy["model_routes"][0]["max_output_tokens"]=1024
policy["fetch_resources"]=[{"id":"approved","url":"https://fixture.gateway.test/approved"}]
policy_path=ROOT/"policy.json";policy_path.write_text(json.dumps(policy))

BASE_PI=["/usr/local/bin/node","/opt/pi/node_modules/@earendil-works/pi-coding-agent/dist/cli.js","--offline","--provider","gateway","--model","gateway-fixture","--thinking","off","--no-session","--no-extensions","--no-mcp","--no-skills","--no-prompt-templates","--no-context-files","--extension","/opt/pi/gateway-extension.ts","--tools","gateway_fetch,bash"]
def gateway(name,argv):
    work=ROOT/name;work.mkdir();audit=ROOT/(name+".audit")
    return ["/gateway","run","--policy",str(policy_path),"--secrets",str(secrets),"--audit",str(audit),"--ca",str(ROOT/"cert.pem"),"--runtime-root",str(RUNTIME),"--workspace",str(work),"--cgroup-root",str(cgroup_root),"--",*argv],work,audit

fixture=Fixture(str(ROOT/"cert.pem"),str(ROOT/"key.pem"))
host_tcp=socket.socket();host_tcp.bind(("127.0.0.1",9443));host_tcp.listen()
host_path=socket.socket(socket.AF_UNIX);host_path.bind("/run/other-run.sock");host_path.listen()
host_abstract=socket.socket(socket.AF_UNIX);host_abstract.bind("\0gateway-host-deputy");host_abstract.listen()
capture=subprocess.Popen(["tcpdump","--immediate-mode","-i","any","-U","-w",str(ROOT/"egress.pcap")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
time.sleep(.2)
try:
    # Preparation failures must never execute the agent command.
    marker="require('node:fs').writeFileSync('/workspace/executed','bad')"
    for name,alter in (
        ("missing-cgroup",lambda args:args.__setitem__(args.index("--cgroup-root")+1,"/missing-cgroup")),
        ("missing-runtime",lambda args:args.__setitem__(args.index("--runtime-root")+1,"/missing-runtime")),
    ):
        args,work,_=gateway(name,["/usr/local/bin/node","-e",marker]);alter(args)
        result=subprocess.run(args,text=True,capture_output=True,timeout=10)
        assert result.returncode!=0 and not(work/"executed").exists(),name
    args,work,_=gateway("missing-bwrap",["/usr/local/bin/node","-e",marker])
    result=subprocess.run(args,text=True,capture_output=True,timeout=10,env={"PATH":"/missing"})
    assert result.returncode!=0 and not(work/"executed").exists()
    args,work,_=gateway("socket-workspace",["/usr/local/bin/node","-e",marker])
    deputy=socket.socket(socket.AF_UNIX);deputy.bind(str(work/"deputy.sock"))
    result=subprocess.run(args,text=True,capture_output=True,timeout=10);deputy.close();(work/"deputy.sock").unlink()
    assert result.returncode!=0 and not(work/"executed").exists()
    for stream in ("stdin","stdout","stderr"):
        args,work,_=gateway("socket-"+stream,["/usr/local/bin/node","-e",marker])
        left,right=socket.socketpair();kwargs={"stdin":subprocess.DEVNULL,"stdout":subprocess.PIPE,"stderr":subprocess.PIPE};kwargs[stream]=right
        result=subprocess.run(args,text=True,timeout=10,**kwargs);left.close();right.close()
        assert result.returncode!=0 and not(work/"executed").exists(),stream
    assert fixture.total_calls==0
    print("PASS setup fails closed: missing launcher/cgroup/runtime, workspace deputy, socket stdio")

    args,work,_=gateway("workspace-quota",["/usr/local/bin/node","-e",marker])
    small_policy=json.loads(json.dumps(policy));small_policy["limits"]["workspace_bytes"]=4096
    bounded=ROOT/"workspace-bounded-policy.json";bounded.write_text(json.dumps(small_policy));args[args.index("--policy")+1]=str(bounded)
    (work/"oversized").write_bytes(b"x"*8192)
    result=subprocess.run(args,text=True,capture_output=True,timeout=10)
    assert result.returncode!=0 and not(work/"executed").exists()
    args,work,_=gateway("temp-quota",["/usr/local/bin/node","-e","try{require('node:fs').writeFileSync('/tmp/huge',Buffer.alloc(65536));process.exit(1)}catch(e){if(e.code!=='ENOSPC')throw e;console.log('TEMP_QUOTA_ENFORCED')}" ])
    small_policy=json.loads(json.dumps(policy));small_policy["limits"]["temp_bytes"]=8192
    bounded=ROOT/"temp-bounded-policy.json";bounded.write_text(json.dumps(small_policy));args[args.index("--policy")+1]=str(bounded)
    result=subprocess.run(args,text=True,capture_output=True,timeout=10)
    assert result.returncode==0 and "TEMP_QUOTA_ENFORCED"in result.stdout,(result.stdout,result.stderr)
    print("PASS quota-backed workspace rejects oversized input; temporary storage physically bounded")

    args,work,_=gateway("orphan",["/usr/local/bin/node","-e","require('node:child_process').spawn('/usr/local/bin/node',['-e','setInterval(()=>{},1000)','gateway-orphan-proof'],{detached:true,stdio:'ignore'}).unref();console.log('ORPHAN_CREATED')"])
    result=subprocess.run(args,text=True,capture_output=True,timeout=10)
    assert result.returncode==0 and "ORPHAN_CREATED"in result.stdout,(result.stdout,result.stderr)
    for entry in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
        try:assert b"gateway-orphan-proof"not in entry.read_bytes(),"orphan child survived"
        except (FileNotFoundError,PermissionError):pass
    print("PASS normal parent exit kills detached arbitrary descendants")

    args,work,_=gateway("pids-quota",["/usr/local/bin/node","-e","const cp=require('node:child_process');let failed=0;const children=[];for(let i=0;i<100;i++){let c=cp.spawn('/bin/sh',['-c','while :; do :; done'],{stdio:'ignore'});c.on('error',e=>{if(e.code==='EAGAIN')failed++});children.push(c)}setTimeout(()=>{for(const c of children)c.kill('SIGKILL');if(!failed)process.exit(1);console.log('PIDS_QUOTA_ENFORCED')},500)"])
    tight=json.loads(json.dumps(policy));tight["limits"]["sandbox_processes"]=32
    bounded=ROOT/"pids-bounded-policy.json";bounded.write_text(json.dumps(tight));args[args.index("--policy")+1]=str(bounded)
    result=subprocess.run(args,text=True,capture_output=True,timeout=10)
    assert result.returncode==0 and "PIDS_QUOTA_ENFORCED"in result.stdout,(result.stdout,result.stderr)
    print("PASS fork saturation reaches kernel process-tree quota")

    args,work,_=gateway("memory-quota",["/usr/local/bin/node","-e","console.log('MEMORY_ALLOCATION_STARTED');const a=[];setInterval(()=>a.push(Buffer.alloc(32<<20,1)),10)"])
    tight=json.loads(json.dumps(policy));tight["limits"]["sandbox_memory_bytes"]=128<<20
    bounded=ROOT/"memory-bounded-policy.json";bounded.write_text(json.dumps(tight));args[args.index("--policy")+1]=str(bounded)
    result=subprocess.run(args,text=True,capture_output=True,timeout=10)
    assert result.returncode!=0 and "MEMORY_ALLOCATION_STARTED"in result.stdout,"memory allocation escaped kernel quota or agent never started"
    print("PASS memory saturation terminates isolated process tree")

    args,work,_=gateway("run-lifetime",["/usr/local/bin/node","-e","setInterval(()=>{},1000)"])
    tight=json.loads(json.dumps(policy));tight["limits"].update(run_seconds=1,model_seconds=1,fetch_seconds=1)
    bounded=ROOT/"lifetime-bounded-policy.json";bounded.write_text(json.dumps(tight));args[args.index("--policy")+1]=str(bounded)
    start=time.monotonic();result=subprocess.run(args,text=True,capture_output=True,timeout=5)
    assert result.returncode!=0 and time.monotonic()-start<3,"idle agent survived run lifetime"
    print("PASS hard wall lifetime terminates idle agent")

    args,work,audit=gateway("normal",BASE_PI+["--mode","json","Exercise the gateway acceptance fixture."])
    inherited=socket.socket();inherited.connect(("127.0.0.1",9443));os.dup2(inherited.fileno(),99)
    result=subprocess.run(args,text=True,capture_output=True,timeout=45,pass_fds=(99,))
    os.close(99);inherited.close()
    (ROOT/"pi-events.jsonl").write_text(result.stdout)
    assert result.returncode==0,(result.stdout,result.stderr)
    events=[json.loads(line)for line in result.stdout.splitlines()if line.startswith("{")]
    assert "GATEWAY_E2E_OK" in result.stdout,result.stdout
    assert (work/"extension-proof.txt").read_text()=="EXTENSION_BYPASS_BLOCKED\n"
    assert (work/"write-proof.txt").read_text()=="WORKSPACE_WRITE_OK\n"
    assert "DIRECT_NETWORK_BLOCKED" in result.stdout,result.stdout
    assert all(not e.get("isError",False)for e in events if e.get("type")=="tool_execution_end"),"Pi tool failed"
    model=[r for r in fixture.requests if "body"in r];fetch=[r for r in fixture.requests if "body"not in r]
    assert len(model)==3 and len(fetch)==1,fixture.requests
    assert all(r["headers"]["Authorization"]=="Bearer gateway-secret-canary" for r in model)
    assert all("Authorization"not in r["headers"] for r in fetch)
    assert all("gateway-local-dummy"not in json.dumps(r["headers"]) for r in fixture.requests)
    assert "gateway-secret-canary"not in result.stdout+result.stderr+audit.read_text()
    records=[json.loads(line)for line in audit.read_text().splitlines()]
    admits=[r for r in records if r["kind"]=="admit"];terminals=[r for r in records if r["kind"]=="terminal" and r.get("outcome")=="complete"]
    assert len(admits)==4 and len(terminals)==4,records
    for admitted in admits:
        terminal=next(r for r in terminals if r["request_id"]==admitted["request_id"])
        assert records.index(admitted)<records.index(terminal)
    (ROOT/"captured-requests.json").write_text(json.dumps([r["body"]for r in model],indent=2))
    print("PASS real pinned Pi: model SSE, fetch tool, shell/grandchild bypass, hostile extension, secret separation")

    fixture.reset("truncate")
    args,work,audit=gateway("truncate",BASE_PI+["--mode","json","Truncate the stream."])
    result=subprocess.run(args,text=True,capture_output=True,timeout=30)
    (ROOT/"pi-truncated.jsonl").write_text(result.stdout)
    assert '"stopReason":"error"' in result.stdout or '"stopReason": "error"'in result.stdout,(result.stdout,result.stderr)
    assert "GATEWAY_E2E_OK"not in result.stdout
    assert len([r for r in fixture.requests if"body"in r])==1,fixture.requests
    assert any(r.get("outcome")=="upstream_incomplete"for r in map(json.loads,audit.read_text().splitlines()))
    print("PASS Pi reports clean EOF without provider finish as incomplete/error")

    for mode in ("bad-length","bad-length-cr","bad-chunk"):
        fixture.reset(mode)
        args,work,audit=gateway(mode,BASE_PI+["--mode","json","Reject premature provider success."])
        result=subprocess.run(args,text=True,capture_output=True,timeout=30)
        (ROOT/("pi-"+mode+".jsonl")).write_text(result.stdout)
        assert '"stopReason":"error"'in result.stdout or '"stopReason": "error"'in result.stdout,(mode,result.stdout,result.stderr)
        records=[json.loads(line)for line in audit.read_text().splitlines()]
        assert any(r["kind"]=="terminal"and r.get("outcome")!="complete"for r in records),(mode,records)
        assert len([r for r in fixture.requests if"body"in r])==1
    print("PASS valid LF/CR SSE success tokens cannot mask malformed Content-Length or chunked HTTP framing")

    fixture.reset("stall")
    args,work,audit=gateway("cancel",BASE_PI+["--mode","rpc"])
    p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    p.stdin.write(json.dumps({"id":"prompt","type":"prompt","message":"Start the stalled stream."})+"\n");p.stdin.flush()
    assert fixture.opened.wait(15),"Pi did not start RPC model request"
    active_groups=list(cgroup_root.glob("gateway-jail-*"));assert len(active_groups)==1,active_groups
    active_group=active_groups[0]
    assert (active_group/"cpu.max").read_text().strip()=="200000 100000"
    assert (active_group/"memory.max").read_text().strip()==str(policy["limits"]["sandbox_memory_bytes"])
    assert (active_group/"pids.max").read_text().strip()==str(policy["limits"]["sandbox_processes"])
    start=time.monotonic();p.stdin.write('{"id":"abort","type":"abort"}\n');p.stdin.flush()
    assert fixture.closed.wait(1),"upstream did not see cancellation in one second"
    p.stdin.close();p.stdin=None
    out,err=p.communicate(timeout=10)
    (ROOT/"pi-cancel.jsonl").write_text(out)
    assert '"stopReason":"aborted"'in out or '"stopReason": "aborted"'in out,(out,err)
    print("PASS Pi RPC cancellation closes actual HTTPS upstream in",round(time.monotonic()-start,3),"seconds")

    fixture.reset("stall")
    args,work,audit=gateway("bridge-outage",BASE_PI+["--mode","json","Start the stream before bridge outage."])
    p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert fixture.opened.wait(15),"Pi did not start bridge outage model request"
    bootstraps=[]
    for entry in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
        try:
            if entry.read_bytes().startswith(b"/gateway\0bootstrap\0"):bootstraps.append(int(entry.parent.name))
        except (FileNotFoundError,PermissionError):pass
    assert len(bootstraps)==1,bootstraps
    os.kill(bootstraps[0],signal.SIGKILL)
    out,err=p.communicate(timeout=5)
    assert p.returncode!=0 and fixture.closed.wait(1),"bridge crash left model request active"
    assert not pathlib.Path("/proc",str(bootstraps[0])).exists()
    print("PASS bridge/bootstrap crash revokes gateway admission and terminates Pi")

    fixture.reset("stall")
    args,work,audit=gateway("outage",BASE_PI+["--mode","json","Start the stream before gateway outage."])
    prior_run_dirs=set(pathlib.Path("/tmp").glob("gateway-run-*"))
    p=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert fixture.opened.wait(15),"Pi did not start outage model request"
    run_dirs=set(pathlib.Path("/tmp").glob("gateway-run-*"))-prior_run_dirs
    assert len(run_dirs)==1,run_dirs
    old_socket=next(iter(run_dirs))/"gateway.sock"
    stale=socket.socket(socket.AF_UNIX);stale.settimeout(1);stale.connect(str(old_socket))
    p.kill();p.communicate(timeout=5)
    assert fixture.closed.wait(1),"gateway outage did not close upstream"
    try:
        stale.sendall(b"GET /healthz HTTP/1.1\r\nHost: gateway.local\r\n\r\n")
        assert stale.recv(1024)==b"","stale connection retained authority"
    except (BrokenPipeError,ConnectionResetError):pass
    stale.close()
    stale=socket.socket(socket.AF_UNIX)
    try:
        stale.connect(str(old_socket));raise AssertionError("stopped listener reused")
    except (FileNotFoundError,ConnectionRefusedError):pass
    finally:stale.close()
    time.sleep(.3)
    # Parent death kills bwrap and its PID namespace; no agent survives outage.
    processes=""
    for entry in pathlib.Path("/proc").glob("[0-9]*/cmdline"):
        try:processes+=entry.read_bytes().replace(b"\0",b" ").decode(errors="replace")+"\n"
        except (FileNotFoundError,PermissionError):pass
    assert "Start the stream before gateway outage."not in processes,processes
    print("PASS supervisor crash terminates isolated Pi tree/upstream and revokes stale socket authority")
    if os.environ.get("GATEWAY_MEASURE")=="1":
        from measure import measure
        measure(gateway,BASE_PI)
finally:
    capture.send_signal(signal.SIGINT);capture.wait(timeout=5);fixture.close()
    packets=command("tcpdump","-nn","-r",str(ROOT/"egress.pcap"),"udp",capture_output=True).stdout
    assert not packets,"sandbox emitted external DNS/UDP packets"
    denied=command("tcpdump","-nn","-r",str(ROOT/"egress.pcap"),"host 1.1.1.1 or host 2606:4700:4700::1111",capture_output=True).stdout
    assert not denied,"sandbox emitted packets toward direct-probe targets"
    syns=command("tcpdump","-nn","-r",str(ROOT/"egress.pcap"),"dst host 11.0.0.2 and dst port 443 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn",capture_output=True).stdout.splitlines()
    assert len(syns)==fixture.total_calls,(len(syns),fixture.total_calls)
    print("PASS outside packet observer:",len(syns),"HTTPS connections match",fixture.total_calls,"broker requests; zero direct/DNS/UDP egress")
    for group in set(cgroup_root.glob("gateway-jail-*"))-baseline_groups:
        assert "populated 0"in (group/"cgroup.events").read_text(),"orphan process survived"
        group.rmdir()
    cgroup_root.rmdir()
    if os.environ.get("GATEWAY_EVIDENCE_DIR"):
        shutil.copytree(ROOT,os.environ["GATEWAY_EVIDENCE_DIR"],dirs_exist_ok=True)
print("Acceptance evidence:",ROOT)

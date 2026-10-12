"""Measure gateway processes separately from Pi and the surrounding Linux VM."""
import pathlib,subprocess,time

def measure(gateway,pi):
    args,work,audit=gateway("idle-measurement",pi+["--mode","rpc"])
    p=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        time.sleep(30)
        assert p.poll()is None,"idle harness exited before measurement"
        processes={}
        for status in pathlib.Path("/proc").glob("[0-9]*/status"):
            try:
                fields=dict(line.split(":",1)for line in status.read_text().splitlines()if":"in line)
                pid=int(fields["Pid"]);parent=int(fields["PPid"])
                cmd=(status.parent/"cmdline").read_bytes().replace(b"\0",b" ").decode(errors="replace")
                processes[pid]=(parent,cmd,int(fields.get("VmRSS","0 kB").split()[0]))
            except (FileNotFoundError,ProcessLookupError,PermissionError):pass
        descendants={p.pid}
        while True:
            expanded=descendants|{pid for pid,(parent,_,_)in processes.items()if parent in descendants}
            if expanded==descendants:break
            descendants=expanded
        go_processes=[(pid,cmd,rss)for pid,(_,cmd,rss)in processes.items()if pid in descendants and (cmd.startswith("/gateway run ")or cmd.startswith("/gateway bootstrap "))]
        assert len(go_processes)==2,go_processes
        rss=sum(rss for _,_,rss in go_processes)
        assert rss<=64*1024,("idle memory target exceeded",rss)
        print("MEASUREMENT Linux gateway/supervisor+bootstrap/bridge idle combined RSS after30s:",rss,"KiB; Pi and VM excluded",flush=True)
        p.stdin.close();p.stdin=None
        out,err=p.communicate(timeout=10)
        assert p.returncode==0,(out,err)
    finally:
        if p.poll()is None:p.kill();p.wait(timeout=5)

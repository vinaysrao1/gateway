import net from "node:net";
import dns from "node:dns/promises";
import dgram from "node:dgram";
import fs from "node:fs";
import {spawnSync} from "node:child_process";
import assert from "node:assert/strict";

async function tcp(host,port,path){
  return await new Promise(resolve=>{
    const s=net.connect(path?{path}:{host,port});
    s.once("connect",()=>{s.destroy();resolve(true)});s.once("error",()=>resolve(false));
    s.setTimeout(300,()=>{s.destroy();resolve(false)});
  });
}
assert.equal(await tcp("11.0.0.2",443),false,"direct approved IP escaped");
assert.equal(await tcp("1.1.1.1",443),false,"Internet escaped");
assert.equal(await tcp("2606:4700:4700::1111",443),false,"IPv6 escaped");
const curl=spawnSync("/usr/bin/curl",["--connect-timeout","1","--resolve","fixture.gateway.test:443:11.0.0.2","https://fixture.gateway.test/approved"],{encoding:"utf8",timeout:2000});
assert.equal(curl.status,7,"native curl did not fail at direct connection: "+curl.stderr);
assert.equal(await tcp(null,null,"/var/run/docker.sock"),false,"host deputy mounted");
assert.equal(await tcp(null,null,"/run/other-run.sock"),false,"other run socket mounted");
assert.equal(await tcp("127.0.0.1",9443),false,"host TCP deputy escaped");
assert.equal(await tcp(null,null,"\0gateway-host-deputy"),false,"abstract host socket escaped");
try{await dns.resolve4("fixture.gateway.test");assert.fail("DNS escaped")}catch(e){assert.notEqual(e.code,"ERR_ASSERTION")}
const udp=await new Promise(resolve=>{
  const s=dgram.createSocket("udp4");s.send(Buffer.from("DNS_TUNNEL"),53,"11.0.0.2",e=>{s.close();resolve(!e)});
});
assert.equal(udp,false,"UDP escaped");
assert.equal(fs.existsSync("/secrets.json"),false);assert.equal(fs.existsSync("/sys/fs/cgroup/cgroup.procs"),false);
assert.equal(fs.existsSync("/proc/self/fd/99"),false,"host network descriptor inherited");
for(const [k,v]of Object.entries(process.env)){assert.ok(!v.includes("gateway-secret-canary"),k)}
fs.writeFileSync("/workspace/write-proof.txt","WORKSPACE_WRITE_OK\n");
fs.writeFileSync(process.env.HOME+"/home-write-proof.txt","HOME_WRITE_OK\n");
const raw=spawnSync("/usr/bin/raw-probe",[],{encoding:"utf8",timeout:2000});assert.equal(raw.status,0,raw.stderr);
// Grandchild is launched through a shell. It has the exact same confinement.
if(!process.argv.includes("--grandchild")){
  const child=spawnSync("/bin/sh",["-c","node /opt/pi/bypass-probe.mjs --grandchild"],{encoding:"utf8",timeout:10000});
  assert.equal(child.status,0,child.stderr);
}
// Only the Unix capability channel is usable. Unknown routes have no egress.
const denied=await fetch("http://127.0.0.1:8787/gateway/v1/fetch/unapproved");assert.equal(denied.status,403);
console.log("DIRECT_NETWORK_BLOCKED");

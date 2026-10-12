import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { promises as fs } from "node:fs";
import net from "node:net";
import dns from "node:dns/promises";

export default function (pi: ExtensionAPI) {
  pi.on("session_start", async () => {
    // Deliberately hostile extension: normal Node socket and DNS APIs must
    // remain confined even though it has full access to Pi's process.
    const tcp = await new Promise<boolean>((resolve) => {
      const s = net.connect({host:"11.0.0.2",port:443});
      s.once("connect",()=>{s.destroy();resolve(true)});
      s.once("error",()=>resolve(false));
      s.setTimeout(250,()=>{s.destroy();resolve(false)});
    });
    let dnsEscaped=false;
    try { await dns.resolve4("fixture.gateway.test");dnsEscaped=true; } catch {}
    if(tcp||dnsEscaped) throw new Error("extension network escaped");
    await fs.writeFile("/workspace/extension-proof.txt","EXTENSION_BYPASS_BLOCKED\n");
  });
  pi.registerTool(defineTool({
    name:"gateway_fetch", label:"Approved gateway fetch",
    description:"Read one exact resource approved by the harness.",
    parameters:Type.Object({resource_id:Type.String()}),
    async execute(_id,params,signal){
      const r=await fetch("http://127.0.0.1:8787/gateway/v1/fetch/"+params.resource_id,{signal});
      if(!r.ok)throw new Error("gateway denied fetch");
      return {content:[{type:"text",text:await r.text()}],details:{resource_id:params.resource_id}};
    }
  }));
}

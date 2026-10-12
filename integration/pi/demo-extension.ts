import { Type } from "@earendil-works/pi-ai";
import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function (pi: ExtensionAPI) {
  pi.registerTool(defineTool({
    name: "gateway_fetch", label: "Fetch approved website through gateway",
    description: "Read the public website approved by the harness.",
    parameters: Type.Object({ resource_id: Type.Literal("approved") }),
    async execute(_id, params, signal) {
      const response = await fetch("http://127.0.0.1:8787/gateway/v1/fetch/" + params.resource_id, { signal });
      if (!response.ok) throw new Error("Gateway fetch failed: " + response.status);
      const text = await response.text();
      return {
        content: [{ type: "text", text: "HTTP " + response.status + "\n" + text }],
        details: { status: response.status, bytes: Buffer.byteLength(text, "utf8") }
      };
    }
  }));
}

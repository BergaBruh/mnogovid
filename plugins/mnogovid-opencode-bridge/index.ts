import { isAbsolute, join, resolve } from "node:path"
import { homedir } from "node:os"

const pluginsRoot = process.env.MNOGOVID_PLUGINS_DIR ?? join(homedir(), "Documents/mnogovid/plugins")

const servers = [
  { name: "mnogovid-code-scanner", script: join(pluginsRoot, "mnogovid-code-scanner/scripts/security_mcp.py") },
  { name: "mnogovid-system-scanner", script: join(pluginsRoot, "mnogovid-system-scanner/scripts/system_mcp.py") },
]

type McpTool = { name: string; description?: string; inputSchema: Record<string, unknown> }

class McpStdioClient {
  private proc: Bun.Subprocess<"pipe", "pipe", "pipe">
  private nextId = 1
  private pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void }>()

  constructor(script: string) {
    this.proc = Bun.spawn(["python3", script], { stdin: "pipe", stdout: "pipe", stderr: "pipe" })
    this.readLoop()
    this.drain(this.proc.stderr)
  }

  kill() {
    this.proc.kill()
  }

  private async readLoop() {
    const decoder = new TextDecoder()
    let buffer = ""
    for await (const chunk of this.proc.stdout) {
      buffer += decoder.decode(chunk, { stream: true })
      let newline = buffer.indexOf("\n")
      while (newline !== -1) {
        const line = buffer.slice(0, newline).trim()
        buffer = buffer.slice(newline + 1)
        if (line) this.dispatch(line)
        newline = buffer.indexOf("\n")
      }
    }
    for (const pending of this.pending.values()) pending.reject(new Error("MCP server exited"))
    this.pending.clear()
  }

  private dispatch(line: string) {
    const message = JSON.parse(line)
    const pending = this.pending.get(message.id)
    if (!pending) return
    this.pending.delete(message.id)
    if (message.error) pending.reject(new Error(message.error.message))
    else pending.resolve(message.result)
  }

  private async drain(stream: ReadableStream<Uint8Array>) {
    for await (const _ of stream) {}
  }

  private send(message: Record<string, unknown>) {
    this.proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n")
    this.proc.stdin.flush()
  }

  request(method: string, params?: unknown): Promise<any> {
    const id = this.nextId++
    return new Promise((resolvePromise, reject) => {
      this.pending.set(id, { resolve: resolvePromise, reject })
      this.send({ id, method, params })
    })
  }

  async start(): Promise<McpTool[]> {
    await this.request("initialize", { protocolVersion: "2025-03-26", capabilities: {}, clientInfo: { name: "opencode-mnogovid", version: "0.1.0" } })
    this.send({ method: "notifications/initialized" })
    const { tools } = await this.request("tools/list")
    return tools
  }

  call(name: string, args: Record<string, unknown>) {
    return this.request("tools/call", { name, arguments: args })
  }
}

export default {
  id: "mnogovid",
  async setup(ctx: {
    location: { directory: string }
    tool: { transform(callback: (editor: any) => void): Promise<unknown> }
  }) {
    const loaded: { server: (typeof servers)[number]; client: McpStdioClient; tools: McpTool[] }[] = []
    for (const server of servers) {
      try {
        const client = new McpStdioClient(server.script)
        loaded.push({ server, client, tools: await client.start() })
      } catch (error) {
        console.error(`mnogovid: ${server.name} failed to start: ${error}`)
      }
    }

    await ctx.tool.transform((editor) => {
      for (const { server, client, tools } of loaded) {
        for (const mcpTool of tools) {
          editor.add({
            name: `${server.name}_${mcpTool.name}`,
            description: mcpTool.description ?? mcpTool.name,
            input: mcpTool.inputSchema,
            async execute(input: Record<string, unknown>) {
              const args = { ...input }
              if (typeof args.workspace === "string" && !isAbsolute(args.workspace)) {
                args.workspace = resolve(ctx.location.directory, args.workspace)
              }
              const result = await client.call(mcpTool.name, args)
              const text = (result.content ?? []).map((part: { text?: string }) => part.text ?? "").join("\n")
              return { content: result.isError ? `error: ${text}` : text }
            },
          })
        }
      }
    })

    return () => loaded.forEach(({ client }) => client.kill())
  },
}

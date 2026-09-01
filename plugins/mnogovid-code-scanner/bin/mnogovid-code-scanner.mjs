#!/usr/bin/env node
import { spawn } from "node:child_process"
import { fileURLToPath } from "node:url"

const script = fileURLToPath(new URL("../scripts/security_mcp.py", import.meta.url))
const child = spawn(process.env.PYTHON ?? "python3", [script], { stdio: "inherit" })

child.on("error", (error) => {
  process.stderr.write(`Unable to start Mnogovid Code Scanner: ${error.message}\n`)
  process.exitCode = 1
})
child.on("exit", (code, signal) => {
  process.exitCode = code ?? (signal ? 1 : 0)
})

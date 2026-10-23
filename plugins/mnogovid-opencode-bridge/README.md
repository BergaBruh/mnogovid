# Mnogovid OpenCode Bridge

OpenCode plugin that loads the MCP tools of `mnogovid-code-scanner` and
`mnogovid-system-scanner` as native OpenCode tools. It starts both Python MCP
servers from this repository and forwards each tool call to them over stdio.
Consent gates and lifecycle checks stay in the servers.

## Requirements

- OpenCode v2 (the plugin uses the v2 `setup(ctx)` API)
- Bun, which OpenCode already bundles
- `python3` on `PATH`
- The scanner executables you intend to run, as described in each plugin's README

## Install

Clone this repository, then point OpenCode at the bridge directory in
`opencode.jsonc`:

```jsonc
{
  "plugins": [
    "/path/to/mnogovid/plugins/mnogovid-opencode-bridge"
  ]
}
```

Restart OpenCode. The tools appear with the prefixes
`mnogovid-code-scanner_` and `mnogovid-system-scanner_`.

Install from npm: **soon**.

## Configuration

- `MNOGOVID_PLUGINS_DIR` overrides the plugins directory. The default is
  `~/Documents/mnogovid/plugins`.
- Relative `workspace` arguments resolve against the OpenCode project directory.

## Notes

- Tool names and schemas come from each server's `tools/list` at startup, so
  the bridge follows the server code without a second list to maintain.
- The bridge runs no scanner itself. Every scan still needs the consent and
  preview steps that the MCP servers enforce.

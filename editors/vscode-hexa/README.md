# HEXA Language Support

Syntax highlighting, editor configuration and file icons for the **HEXA**
programming language and its file formats.

## Features

- **Syntax highlighting** for `.he` source files (`source.hexa`) matching the
  actual compiler lexer: all keywords, the security type lattice
  (`secret`, `key`, `plaintext`, `ciphertext`, `password`, …), string /
  byte-string / char literals with escapes, hex/bin/decimal numbers,
  nested `/* */` and `//` comments, attributes, and prelude functions.
- **Language configuration**: auto-closing pairs for `{}` `[]` `()`, `"` `'`,
  block/line comment toggling, `// region` / `// endregion` folding.
- **File icon theme "HEXA File Icons"**: distinct icons for `.he` sources,
  `.hexa` encrypted containers, `.hxpkg` packages and `hexa.toml`.

## Using

1. Install the extension (from the VS Code Marketplace, or
   `code --install-extension hexa-language-0.1.0.vsix`).
2. For the file icons, open **File → Preferences → File Icon Theme** and pick
   **HEXA File Icons**.
3. Open or create any `*.he` file — it is recognized automatically.

## Development

```bash
npm install -g @vscode/vsce
cd editors/vscode-hexa
vsce package          # → hexa-language-0.1.0.vsix
code --install-extension hexa-language-0.1.0.vsix
```

Icons are shared from `assets/icons/` (Apache-2.0).

## License

Apache-2.0, same as the HEXA toolchain.
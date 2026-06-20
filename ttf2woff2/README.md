# ttf2woff2

Convert TrueType/OpenType fonts (`.ttf` / `.otf`) to **WOFF2** in Go.

WOFF2 is an sfnt font whose table data is Brotli-compressed inside a small
container. This tool parses the sfnt table directory, repacks it into the WOFF2
layout, and Brotli-compresses the table data. Tables are stored with the *null*
transform (the spec's optional `glyf` transform is skipped) — fully valid, and
Brotli does the size work. Typical saving vs raw TTF is ~50–56%.

## Build

```sh
go build -o ttf2woff2 .
```

## Usage

```sh
ttf2woff2 [-o outdir] <font.ttf | dir> ...
```

- A **file** argument is converted to `<name>.woff2`.
- A **directory** argument converts every `.ttf`/`.otf` inside it.
- `-o outdir` writes all output there (default: next to each input).

```sh
# one file, output beside it
ttf2woff2 Geist.ttf

# a whole fonts folder into ./dist
ttf2woff2 -o dist ./web/fonts
```

Example:

```
✓ web/fonts/Geist.ttf → web/fonts/Geist.woff2   164.8 KiB → 71.7 KiB  (−56%)
```

## Notes

- **Dependency:** `github.com/andybalholm/brotli` (MIT). WOFF2 *mandates* Brotli
  and the Go standard library has no Brotli codec, so this one dependency is
  unavoidable. Everything else — sfnt parsing, the WOFF2 container, the table
  directory, `UIntBase128` — is hand-written stdlib.
- TrueType Collections (`.ttc`) are not supported (single fonts only).
- Validated by round-tripping output through `fontTools` (the reference WOFF2
  decoder); fonts load in all current browsers.

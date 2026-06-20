// Command ttf2woff2 converts TrueType/OpenType fonts (.ttf/.otf) to WOFF2.
//
// WOFF2 (https://www.w3.org/TR/WOFF2/) is just an sfnt font whose table data is
// Brotli-compressed inside a small container. This tool parses the sfnt table
// directory, repacks it into the WOFF2 layout, and Brotli-compresses the table
// data. Tables are stored with the *null* transform (the spec's optional glyf
// transform is skipped), which keeps the encoder simple and is fully valid —
// Brotli does the heavy lifting and the result loads in every browser.
//
// Go's standard library has no Brotli codec, and WOFF2 mandates Brotli, so the
// one dependency is github.com/andybalholm/brotli. Everything else is stdlib.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/andybalholm/brotli"
)

// knownTags is the WOFF2 fixed table-tag index (W3C WOFF2 §5.2, Table 6). A
// table whose tag appears here is encoded by its 6-bit index; any other tag
// uses the escape index 63 followed by the literal 4-byte tag.
var knownTags = []string{
	"cmap", "head", "hhea", "hmtx", "maxp", "name", "OS/2", "post",
	"cvt ", "fpgm", "glyf", "loca", "prep", "CFF ", "VORG", "EBDT",
	"EBLC", "gasp", "hdmx", "kern", "LTSH", "PCLT", "VDMX", "vhea",
	"vmtx", "BASE", "GDEF", "GPOS", "GSUB", "EBSC", "JSTF", "MATH",
	"CBDT", "CBLC", "COLR", "CPAL", "SVG ", "sbix", "acnt", "avar",
	"bdat", "bloc", "bsln", "cvar", "fdsc", "feat", "fmtx", "fvar",
	"gvar", "hsty", "just", "lcar", "mort", "morx", "opbd", "prop",
	"trak", "Zapf", "Silf", "Glat", "Gloc", "Feat", "Sill",
}

func tagIndex(tag string) byte {
	for i, t := range knownTags {
		if t == tag {
			return byte(i)
		}
	}
	return 63
}

// uintBase128 appends n in WOFF2 UIntBase128 form: big-endian, 7 bits per byte,
// MSB set on every byte except the last, shortest encoding (no leading 0x80).
func uintBase128(b []byte, n uint32) []byte {
	var tmp [5]byte
	i := 4
	tmp[i] = byte(n & 0x7f)
	for n >>= 7; n > 0; n >>= 7 {
		i--
		tmp[i] = byte(n&0x7f) | 0x80
	}
	return append(b, tmp[i:]...)
}

type sfntTable struct {
	tag  string
	data []byte
}

// parseSfnt reads the sfnt header + table directory and slices out each table.
func parseSfnt(b []byte) (flavor uint32, tables []sfntTable, err error) {
	if len(b) < 12 {
		return 0, nil, errors.New("file too small to be a font")
	}
	flavor = binary.BigEndian.Uint32(b[0:4])
	switch flavor {
	case 0x74746366: // 'ttcf'
		return 0, nil, errors.New("TrueType Collections (.ttc) are not supported")
	case 0x00010000, 0x4F54544F /*OTTO*/, 0x74727565 /*true*/, 0x74797031 /*typ1*/ :
	default:
		return 0, nil, fmt.Errorf("unrecognized sfnt version %#08x (not a TTF/OTF)", flavor)
	}
	numTables := int(binary.BigEndian.Uint16(b[4:6]))
	off := 12
	for i := 0; i < numTables; i++ {
		if off+16 > len(b) {
			return 0, nil, errors.New("truncated table directory")
		}
		tag := string(b[off : off+4])
		tOff := binary.BigEndian.Uint32(b[off+8 : off+12])
		tLen := binary.BigEndian.Uint32(b[off+12 : off+16])
		if int(tOff) > len(b) || int(tOff)+int(tLen) > len(b) {
			return 0, nil, fmt.Errorf("table %q extends past end of file", tag)
		}
		tables = append(tables, sfntTable{tag: tag, data: b[tOff : tOff+tLen]})
		off += 16
	}
	if len(tables) == 0 {
		return 0, nil, errors.New("font has no tables")
	}
	return flavor, tables, nil
}

// encodeWOFF2 builds a WOFF2 file from a parsed sfnt, storing every table with
// the null transform and Brotli-compressing the concatenated table data.
func encodeWOFF2(flavor uint32, tables []sfntTable) ([]byte, error) {
	var dir bytes.Buffer
	var data []byte
	totalSfntSize := 12 + 16*len(tables) // reconstructed sfnt: header + directory…
	for _, t := range tables {
		idx := tagIndex(t.tag)
		flags := idx
		if t.tag == "glyf" || t.tag == "loca" {
			flags |= 3 << 6 // null transform for glyf/loca is transform version 3
		}
		dir.WriteByte(flags)
		if idx == 63 {
			dir.WriteString(t.tag) // arbitrary tag: 4 literal bytes
		}
		dir.Write(uintBase128(nil, uint32(len(t.data)))) // origLength; no transformLength (null transform)
		data = append(data, t.data...)
		totalSfntSize += (len(t.data) + 3) &^ 3 // …+ each table padded to 4 bytes
	}

	var comp bytes.Buffer
	bw := brotli.NewWriterLevel(&comp, brotli.BestCompression)
	if _, err := bw.Write(data); err != nil {
		return nil, err
	}
	if err := bw.Close(); err != nil {
		return nil, err
	}
	compressed := comp.Bytes()

	total := 48 + dir.Len() + len(compressed)
	var out bytes.Buffer
	w16 := func(v uint16) { binary.Write(&out, binary.BigEndian, v) }
	w32 := func(v uint32) { binary.Write(&out, binary.BigEndian, v) }
	w32(0x774F4632)              // signature 'wOF2'
	w32(flavor)                  // flavor = original sfnt version
	w32(uint32(total))           // length (whole file)
	w16(uint16(len(tables)))     // numTables
	w16(0)                       // reserved
	w32(uint32(totalSfntSize))   // totalSfntSize (uncompressed)
	w32(uint32(len(compressed))) // totalCompressedSize
	w16(1)                       // majorVersion
	w16(0)                       // minorVersion
	w32(0)                       // metaOffset
	w32(0)                       // metaLength
	w32(0)                       // metaOrigLength
	w32(0)                       // privOffset
	w32(0)                       // privLength
	out.Write(dir.Bytes())
	out.Write(compressed)
	return out.Bytes(), nil
}

func convert(inPath, outPath string) (inSz, outSz int, err error) {
	raw, err := os.ReadFile(inPath)
	if err != nil {
		return
	}
	flavor, tables, err := parseSfnt(raw)
	if err != nil {
		return
	}
	w2, err := encodeWOFF2(flavor, tables)
	if err != nil {
		return
	}
	if err = os.WriteFile(outPath, w2, 0o644); err != nil {
		return
	}
	return len(raw), len(w2), nil
}

func human(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

// expandInputs turns each argument into a list of font files: a directory
// yields its .ttf/.otf children, a file is taken as-is.
func expandInputs(args []string) []string {
	var out []string
	for _, a := range args {
		if fi, err := os.Stat(a); err == nil && fi.IsDir() {
			entries, _ := os.ReadDir(a)
			for _, e := range entries {
				if ext := strings.ToLower(filepath.Ext(e.Name())); ext == ".ttf" || ext == ".otf" {
					out = append(out, filepath.Join(a, e.Name()))
				}
			}
			continue
		}
		out = append(out, a)
	}
	return out
}

func main() {
	outDir := flag.String("o", "", "output directory (default: write each .woff2 next to its input)")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "ttf2woff2 — convert TTF/OTF fonts to WOFF2")
		fmt.Fprintln(os.Stderr, "\nusage: ttf2woff2 [-o outdir] <font.ttf | dir> ...")
		fmt.Fprintln(os.Stderr, "\nA directory argument converts every .ttf/.otf inside it.")
		flag.PrintDefaults()
	}
	flag.Parse()
	inputs := expandInputs(flag.Args())
	if len(inputs) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "cannot create %s: %v\n", *outDir, err)
			os.Exit(1)
		}
	}

	var fail, totIn, totOut int
	for _, in := range inputs {
		base := strings.TrimSuffix(filepath.Base(in), filepath.Ext(in)) + ".woff2"
		out := filepath.Join(filepath.Dir(in), base)
		if *outDir != "" {
			out = filepath.Join(*outDir, base)
		}
		inSz, outSz, err := convert(in, out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", in, err)
			fail++
			continue
		}
		totIn += inSz
		totOut += outSz
		fmt.Printf("✓ %s → %s   %s → %s  (−%.0f%%)\n", in, out, human(inSz), human(outSz), 100*(1-float64(outSz)/float64(inSz)))
	}
	if len(inputs) > 1 {
		fmt.Printf("\n%d converted, %d failed   total %s → %s  (−%.0f%%)\n",
			len(inputs)-fail, fail, human(totIn), human(totOut), 100*(1-float64(totOut)/float64(max1(totIn))))
	}
	if fail > 0 {
		os.Exit(1)
	}
}

func max1(n int) int {
	if n == 0 {
		return 1
	}
	return n
}

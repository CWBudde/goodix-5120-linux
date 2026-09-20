// Package winreg is a minimal, read-only reader for Windows registry hive
// files (the "regf" on-disk format).
//
// It exists only to support offline DPAPI master-key recovery (see
// internal/dpapi): it reads a handful of values and key class names out of the
// SYSTEM and SECURITY hives and nothing more. It never writes, and it opens no
// device. Big-data (">16344 byte") values and volatile keys are intentionally
// unsupported because none of the values this tool needs use them.
//
// Format references: the "regf" base block carries the root cell offset at
// 0x24; cell data lives in "hbin" blocks starting at file offset 0x1000, and a
// cell offset is relative to that. Key nodes ("nk"), value keys ("vk") and the
// subkey lists ("lf"/"lh"/"li"/"ri") are parsed just enough to walk a path.
package winreg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf16"
)

const hbinBase = 0x1000

// Hive is a parsed, read-only registry hive held in memory.
type Hive struct {
	data    []byte
	rootOff uint32 // root cell offset, relative to hbinBase
}

// Value types we care about.
const (
	RegSZ     = 1
	RegBinary = 3
	RegDWord  = 4
)

// Open reads a hive file fully into memory and validates its header.
func Open(path string) (*Hive, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) < hbinBase || string(b[0:4]) != "regf" {
		return nil, fmt.Errorf("winreg: %s is not a regf hive", path)
	}
	root := binary.LittleEndian.Uint32(b[0x24:0x28])
	return &Hive{data: b, rootOff: root}, nil
}

// cell returns the data bytes of the cell at the given hbin-relative offset,
// i.e. the bytes after the 4-byte cell size header.
func (h *Hive) cell(off uint32) ([]byte, error) {
	pos := int(hbinBase) + int(off)
	if pos < 0 || pos+4 > len(h.data) {
		return nil, fmt.Errorf("winreg: cell offset 0x%x out of range", off)
	}
	size := int32(binary.LittleEndian.Uint32(h.data[pos : pos+4]))
	if size < 0 {
		size = -size // negative size marks an allocated cell
	}
	end := pos + int(size)
	if size < 4 || end > len(h.data) {
		return nil, fmt.Errorf("winreg: cell at 0x%x has bad size %d", off, size)
	}
	return h.data[pos+4 : end], nil
}

// nk is a parsed key node, holding only what path-walking needs.
type nk struct {
	h            *Hive
	subkeyCount  uint32
	subkeyList   uint32
	valueCount   uint32
	valueList    uint32
	classOff     uint32
	classLen     uint16
	name         string
}

func (h *Hive) readNK(off uint32) (*nk, error) {
	c, err := h.cell(off)
	if err != nil {
		return nil, err
	}
	if len(c) < 0x50 || string(c[0:2]) != "nk" {
		return nil, errors.New("winreg: not an nk cell")
	}
	nameLen := binary.LittleEndian.Uint16(c[0x48:0x4a])
	n := &nk{
		h:           h,
		subkeyCount: binary.LittleEndian.Uint32(c[0x14:0x18]),
		subkeyList:  binary.LittleEndian.Uint32(c[0x1c:0x20]),
		valueCount:  binary.LittleEndian.Uint32(c[0x24:0x28]),
		valueList:   binary.LittleEndian.Uint32(c[0x28:0x2c]),
		classOff:    binary.LittleEndian.Uint32(c[0x30:0x34]),
		classLen:    binary.LittleEndian.Uint16(c[0x4a:0x4c]),
	}
	flags := binary.LittleEndian.Uint16(c[0x02:0x04])
	if int(0x4c+int(nameLen)) <= len(c) {
		raw := c[0x4c : 0x4c+int(nameLen)]
		if flags&0x20 != 0 { // ASCII (compressed) name
			n.name = string(raw)
		} else {
			n.name = decodeUTF16(raw)
		}
	}
	return n, nil
}

// root returns the hive's root key node.
func (h *Hive) root() (*nk, error) { return h.readNK(h.rootOff) }

// subkeyOffsets collects the NK offsets referenced by a subkey list cell,
// following ri (index-root) lists into their leaves.
func (h *Hive) subkeyOffsets(listOff uint32) ([]uint32, error) {
	if listOff == 0 || listOff == 0xffffffff {
		return nil, nil
	}
	c, err := h.cell(listOff)
	if err != nil {
		return nil, err
	}
	if len(c) < 4 {
		return nil, errors.New("winreg: short subkey list")
	}
	sig := string(c[0:2])
	count := int(binary.LittleEndian.Uint16(c[2:4]))
	var offs []uint32
	switch sig {
	case "lf", "lh": // leaf: [offset:4][hash:4] per entry
		for i := 0; i < count; i++ {
			o := 4 + i*8
			if o+4 > len(c) {
				break
			}
			offs = append(offs, binary.LittleEndian.Uint32(c[o:o+4]))
		}
	case "li": // leaf: [offset:4] per entry
		for i := 0; i < count; i++ {
			o := 4 + i*4
			if o+4 > len(c) {
				break
			}
			offs = append(offs, binary.LittleEndian.Uint32(c[o:o+4]))
		}
	case "ri": // index root: entries point to further lists
		for i := 0; i < count; i++ {
			o := 4 + i*4
			if o+4 > len(c) {
				break
			}
			sub, err := h.subkeyOffsets(binary.LittleEndian.Uint32(c[o : o+4]))
			if err != nil {
				return nil, err
			}
			offs = append(offs, sub...)
		}
	default:
		return nil, fmt.Errorf("winreg: unknown subkey list sig %q", sig)
	}
	return offs, nil
}

// child finds a direct subkey by name (case-insensitive).
func (n *nk) child(name string) (*nk, error) {
	offs, err := n.h.subkeyOffsets(n.subkeyList)
	if err != nil {
		return nil, err
	}
	for _, o := range offs {
		sk, err := n.h.readNK(o)
		if err != nil {
			continue
		}
		if strings.EqualFold(sk.name, name) {
			return sk, nil
		}
	}
	return nil, fmt.Errorf("winreg: subkey %q not found", name)
}

// keyAt walks a backslash-separated path from the root.
func (h *Hive) keyAt(path string) (*nk, error) {
	cur, err := h.root()
	if err != nil {
		return nil, err
	}
	for _, part := range strings.Split(path, `\`) {
		if part == "" {
			continue
		}
		cur, err = cur.child(part)
		if err != nil {
			return nil, err
		}
	}
	return cur, nil
}

// ClassName returns the UTF-16 class-name string of the key at path. The four
// LSA keys (JD/Skew1/GBG/Data) carry the scrambled boot key here.
func (h *Hive) ClassName(path string) (string, error) {
	k, err := h.keyAt(path)
	if err != nil {
		return "", err
	}
	if k.classLen == 0 {
		return "", fmt.Errorf("winreg: key %q has no class name", path)
	}
	c, err := h.cell(k.classOff)
	if err != nil {
		return "", err
	}
	if int(k.classLen) > len(c) {
		return "", fmt.Errorf("winreg: class name for %q truncated", path)
	}
	return decodeUTF16(c[:k.classLen]), nil
}

// value returns the raw data and type of a named value of the key at path.
// An empty name selects the key's default value.
func (h *Hive) value(path, name string) ([]byte, uint32, error) {
	k, err := h.keyAt(path)
	if err != nil {
		return nil, 0, err
	}
	if k.valueCount == 0 || k.valueList == 0 || k.valueList == 0xffffffff {
		return nil, 0, fmt.Errorf("winreg: key %q has no values", path)
	}
	list, err := h.cell(k.valueList)
	if err != nil {
		return nil, 0, err
	}
	for i := 0; i < int(k.valueCount); i++ {
		o := i * 4
		if o+4 > len(list) {
			break
		}
		vkOff := binary.LittleEndian.Uint32(list[o : o+4])
		vname, data, typ, err := h.readVK(vkOff)
		if err != nil {
			continue
		}
		if strings.EqualFold(vname, name) {
			return data, typ, nil
		}
	}
	return nil, 0, fmt.Errorf("winreg: value %q not found under %q", name, path)
}

// Binary returns the default (unnamed) REG_BINARY value of the key at path.
func (h *Hive) Binary(path string) ([]byte, error) {
	d, _, err := h.value(path, "")
	return d, err
}

// DWord returns a named REG_DWORD value of the key at path.
func (h *Hive) DWord(path, name string) (uint32, error) {
	d, _, err := h.value(path, name)
	if err != nil {
		return 0, err
	}
	if len(d) < 4 {
		return 0, fmt.Errorf("winreg: value %q under %q is not a dword", name, path)
	}
	return binary.LittleEndian.Uint32(d[:4]), nil
}

func (h *Hive) readVK(off uint32) (name string, data []byte, typ uint32, err error) {
	c, cerr := h.cell(off)
	if cerr != nil {
		return "", nil, 0, cerr
	}
	if len(c) < 0x14 || string(c[0:2]) != "vk" {
		return "", nil, 0, errors.New("winreg: not a vk cell")
	}
	nameLen := binary.LittleEndian.Uint16(c[0x02:0x04])
	dataLen := binary.LittleEndian.Uint32(c[0x04:0x08])
	dataOff := binary.LittleEndian.Uint32(c[0x08:0x0c])
	typ = binary.LittleEndian.Uint32(c[0x0c:0x10])
	flags := binary.LittleEndian.Uint16(c[0x10:0x12])
	if int(0x14+int(nameLen)) <= len(c) {
		raw := c[0x14 : 0x14+int(nameLen)]
		if flags&0x01 != 0 {
			name = string(raw)
		} else {
			name = decodeUTF16(raw)
		}
	}
	const inlineFlag = 0x80000000
	if dataLen&inlineFlag != 0 { // data stored in the offset field itself
		n := int(dataLen &^ inlineFlag)
		if n > 4 {
			n = 4
		}
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, dataOff)
		return name, buf[:n], typ, nil
	}
	if dataLen == 0 {
		return name, nil, typ, nil
	}
	if dataLen > 16344 {
		return "", nil, 0, errors.New("winreg: big-data values unsupported")
	}
	dc, derr := h.cell(dataOff)
	if derr != nil {
		return "", nil, 0, derr
	}
	if int(dataLen) > len(dc) {
		return "", nil, 0, errors.New("winreg: value data truncated")
	}
	return name, dc[:dataLen], typ, nil
}

func decodeUTF16(b []byte) string {
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		u = append(u, binary.LittleEndian.Uint16(b[i:i+2]))
	}
	s := string(utf16.Decode(u))
	return strings.TrimRight(s, "\x00")
}

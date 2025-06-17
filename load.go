package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"log"
	"os"
	"strings"

	demangle "github.com/ianlancetaylor/demangle"
	"github.com/erikgeiser/ar"
)

var exposed = []string{
	"_lfi_retfn",
	"_lfi_pause",
	"_lfi_thread_create",
	"_lfi_thread_destroy",
	//NOTE(abhishek): expose jemalloc moz_ prefixed
	// arena allocation functions
	"moz_arena_malloc",
	"moz_arena_realloc",
	"moz_arena_calloc",
	"free",
}

type ExportInfo struct {
	Name string
	IsGlobal bool
}

func IsExport(sym string, exports map[string]bool) bool {
	if len(exports) > 0 && exports[sym] {
		return true
	}

	dsym := demangle.Filter(sym)
	_, after, found := strings.Cut(dsym, " ")

	if strings.HasPrefix(dsym, "js::") || strings.HasPrefix(dsym, "JS::") || strings.HasPrefix(dsym, "sandbox::") || strings.HasPrefix(dsym, "JS_") || strings.Contains(dsym, "ProfilingStack") || strings.Contains(dsym, "JSStructuredCloneData") || strings.Contains(dsym, "JSAutoRealm") || strings.Contains(dsym, "JSAutoStructuredCloneBuffer") || strings.Contains(dsym, "JSErrorReport") || strings.Contains(dsym, "JSErrorNotes") || strings.Contains(dsym, "JSAutoNullableRealm") || strings.Contains(dsym, "JSPrincipalsWithOps") {
		return true
	} else if found && (strings.HasPrefix(after, "js::") || strings.HasPrefix(after, "JS::") || strings.HasPrefix(after, "sandbox::") || strings.HasPrefix(after, "JS_")) {
		return true
	}

	return false
}

func ObjGetExports(file *elf.File, es map[string]bool) []ExportInfo {
	syms, err := file.Symbols()
	if err != nil {
		fatal(err)
	}
	var exports []ExportInfo
	for _, sym := range syms {
		if IsExport(sym.Name, es) && (elf.ST_BIND(sym.Info) == elf.STB_GLOBAL && elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Section != elf.SHN_UNDEF) {
			if sym.Name == "_init" || sym.Name == "_fini" {
				// Musl inserts these symbols on shared libraries, but after we
				// compile the stub they will be linked internally, and should
				// not be exported.
				continue
			}
			exports = append(exports, ExportInfo{ Name: sym.Name, IsGlobal: true })
		}
		if IsExport(sym.Name, es) && (elf.ST_BIND(sym.Info) == elf.STB_WEAK && elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Section != elf.SHN_UNDEF) {
			if sym.Name == "_init" || sym.Name == "_fini" {
				// Musl inserts these symbols on shared libraries, but after we
				// compile the stub they will be linked internally, and should
				// not be exported.
				continue
			}
			exports = append(exports, ExportInfo{ Name: sym.Name, IsGlobal: false })
		}
	}
	ObjGetStackArgs(file, es)
	return exports
}

func DynamicGetExports(dynlib *os.File, es map[string]bool) ([]ExportInfo, StackArgInfo) {
	f, err := elf.NewFile(dynlib)
	if err != nil {
		fatal(err)
	}
	return ObjGetExports(f, es), ObjGetStackArgs(f, es)
}

func StaticGetExports(staticlib *os.File, es map[string]bool) ([]ExportInfo, StackArgInfo) {
	r, err := ar.NewReader(staticlib)
	if err != nil {
		fatal(err)
	}
	var exports []ExportInfo
	for {
		_, err := r.Next()
		if err != nil {
			break
		}
		data, err := io.ReadAll(r)
		if err != nil {
			continue
		}
		b := bytes.NewReader(data)
		ef, err := elf.NewFile(b)
		if err != nil {
			continue
		}
		exports = append(exports, ObjGetExports(ef, es)...)
	}
	return exports, StackArgInfo{}
}

type StackArgInfo struct {
	Fn   uint64
	Sret uint32
	Args map[string][]StackArg
}

type StackArg struct {
	Offset uint32
	Size   uint32
}

func ObjGetStackArgs(file *elf.File, es map[string]bool) StackArgInfo {
	sec := file.Section(".stack_args")
	if sec == nil {
		return StackArgInfo{}
	}

	syms, err := file.Symbols()
	if err != nil {
		log.Fatal(err)
	}
	symtab := make(map[uint64]string)
	for _, sym := range syms {
		symtab[sym.Value] = sym.Name
	}

	info := StackArgInfo{
		Args: make(map[string][]StackArg),
	}

	b := make([]byte, 8)
	idx := uint64(0)
	for idx < sec.Size {
		sec.ReadAt(b, int64(idx))
		idx += 8
		info.Fn = binary.LittleEndian.Uint64(b)

		sec.ReadAt(b, int64(idx))
		idx += 4
		info.Sret = binary.LittleEndian.Uint32(b)

		sec.ReadAt(b, int64(idx))
		idx += 4
		entries := binary.LittleEndian.Uint32(b)

		var args []StackArg
		for i := uint32(0); i < entries; i++ {
			// stack offset
			sec.ReadAt(b, int64(idx))
			idx += 4
			offset := binary.LittleEndian.Uint32(b)
			// size
			sec.ReadAt(b, int64(idx))
			idx += 4
			size := binary.LittleEndian.Uint32(b)

			args = append(args, StackArg{
				Offset: offset,
				Size:   size,
			})
		}

		sym := symtab[info.Fn]
		info.Args[sym] = args
	}

	//fmt.Println(info)
	return info
}

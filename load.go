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

func DynamicGetExports(dynlib *os.File, es map[string]bool) ([]ExportInfo, map[string]StackArgInfo) {
	f, err := elf.NewFile(dynlib)
	if err != nil {
		fatal(err)
	}

	stackArgs, ok := ObjGetStackArgs(f, es)
	if !ok {
		fatal(err)
	}
	
	return ObjGetExports(f, es), stackArgs
}

func StaticGetExports(staticlib *os.File, es map[string]bool) ([]ExportInfo, map[string]StackArgInfo) {
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
	return exports, nil
}

type StackArgInfo struct {
	Sret uint32
	Args []StackArg
}

type StackArg struct {
	Offset uint32
	Size   uint32
}

func ObjGetStackArgs(file *elf.File, es map[string]bool) (map[string]StackArgInfo, bool) {
	sec := file.Section(".stack_args")
	if sec == nil {
		return nil, false
	}

	syms, err := file.Symbols()
	if err != nil {
		log.Fatal(err)
	}
	symtab := make(map[uint64]string)
	for _, sym := range syms {
		symtab[sym.Value] = sym.Name
	}

	info := make(map[string]StackArgInfo)

	b64 := make([]byte, 8)
	b32 := make([]byte, 4)
	idx := uint64(0)
	for idx < sec.Size {
		sec.ReadAt(b64, int64(idx))
		idx += 8
		fn := binary.LittleEndian.Uint64(b64)

		sec.ReadAt(b32, int64(idx))
		idx += 4
		sret := binary.LittleEndian.Uint32(b32)

		sec.ReadAt(b32, int64(idx))
		idx += 4
		entries := binary.LittleEndian.Uint32(b32)

		var args []StackArg
		for i := uint32(0); i < entries; i++ {
			// stack offset
			sec.ReadAt(b32, int64(idx))
			idx += 4
			offset := binary.LittleEndian.Uint32(b32)
			// size
			sec.ReadAt(b32, int64(idx))
			idx += 4
			size := binary.LittleEndian.Uint32(b32)

			args = append(args, StackArg{
				Offset: offset,
				Size:   size,
			})
		}

		sym := symtab[fn]
		info[sym] = StackArgInfo{
			Sret: sret,
			Args: args,
		}
	}

	return info, true
}

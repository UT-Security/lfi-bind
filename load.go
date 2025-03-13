package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/erikgeiser/ar"
	demangle "github.com/ianlancetaylor/demangle"
)

var exposed = []string{
	"_lfi_retfn",
	"_lfi_pause",
	"_lfi_thread_create",
	"_lfi_thread_destroy",
	"moz_arena_malloc",
	"moz_arena_calloc",
	"moz_arena_realloc",
	"free",
}

type GetterGen struct {
	Symbol string
	Getter string
	Deref  bool
}

var getters = []GetterGen{
	{Symbol: "_ZN2js16FunctionClassPtrE", Getter: "_ZN2js19GetFunctionClassPtrEv", Deref: true},
	{Symbol: "_ZN2js24FunctionExtendedClassPtrE", Getter: "_ZN2js27GetFunctionExtendedClassPtrEv", Deref: true},

	{Symbol: "_ZN2JS15NullHandleValueE", Getter: "_ZN2JS18GetNullHandleValueEv", Deref: true},
	{Symbol: "_ZN2JS20UndefinedHandleValueE", Getter: "_ZN2JS23GetUndefinedHandleValueEv", Deref: true},
	{Symbol: "_ZN2JS15TrueHandleValueE", Getter: "_ZN2JS18GetTrueHandleValueEv", Deref: true},
	{Symbol: "_ZN2JS16FalseHandleValueE", Getter: "_ZN2JS19GetFalseHandleValueEv", Deref: true},
	{Symbol: "_ZN2JS18NothingHandleValueE", Getter: "_ZN2JS21GetNothingHandleValueEv", Deref: true},

	{Symbol: "_ZN2js11MallocArenaE", Getter: "_ZN2js14GetMallocArenaEv", Deref: true},
	{Symbol: "_ZN2js24ArrayBufferContentsArenaE", Getter: "_ZN2js27GetArrayBufferContentsArenaEv", Deref: true},
	{Symbol: "_ZN2js17StringBufferArenaE", Getter: "_ZN2js20GetStringBufferArenaEv", Deref: true},

	{Symbol: "_ZN2JS21DefaultGlobalClassOpsE", Getter: "_ZN2JS24GetDefaultGlobalClassOpsEv", Deref: false},

	{Symbol: "_ZN2JS21VoidHandlePropertyKeyE", Getter: "_ZN2JS24GetVoidHandlePropertyKeyEv", Deref: true},

	{Symbol: "_ZN2js13ProxyClassOpsE", Getter: "_ZN2js15ProxyClassOps_pEv", Deref: false},
	{Symbol: "_ZN2js19ProxyClassExtensionE", Getter: "_ZN2js21ProxyClassExtension_pEv", Deref: false},
	{Symbol: "_ZN2js14ProxyObjectOpsE", Getter: "_ZN2js16ProxyObjectOps_pEv", Deref: false},
	{Symbol: "_ZN2js10ProxyClassE", Getter: "_ZN2js12ProxyClass_pEv", Deref: false},

	{Symbol: "_ZN2JS11ArrayBuffer13UnsharedClassE", Getter: "_ZN2JS11ArrayBuffer15UnsharedClass_pEv", Deref: true},
	{Symbol: "_ZN2JS11ArrayBuffer11SharedClassE", Getter: "_ZN2JS11ArrayBuffer13SharedClass_pEv", Deref: true},
	{Symbol: "_ZN2JS8DataView8ClassPtrE", Getter: "_ZN2JS8DataView11GetClassPtrEv", Deref: true},
	{Symbol: "_ZN2JS15TypedArray_base7classesE", Getter: "_ZN2JS15TypedArray_base10getClassesEv", Deref: true},
}

func IsExport(sym string, exports map[string]bool) bool {
	dsym := demangle.Filter(sym)
	_, after, found := strings.Cut(dsym, " ")

	if strings.HasPrefix(dsym, "js::") || strings.HasPrefix(dsym, "JS::") || strings.HasPrefix(dsym, "JS_") || strings.Contains(dsym, "ProfilingStack") || strings.Contains(dsym, "JSStructuredCloneData") || strings.Contains(dsym, "JSAutoRealm") || strings.Contains(dsym, "JSAutoStructuredCloneBuffer") || strings.Contains(dsym, "JSErrorReport") || strings.Contains(dsym, "JSErrorNotes") || strings.Contains(dsym, "JSAutoNullableRealm") || strings.Contains(dsym, "JSPrincipalsWithOps") {
		return true
	} else if found && (strings.HasPrefix(after, "js::") || strings.HasPrefix(after, "JS::") || strings.HasPrefix(after, "JS_")) {
		return true
	}

	return false
}

func ObjGetExports(file *elf.File, es map[string]bool) []string {
	syms, err := file.Symbols()
	if err != nil {
		fatal(err)
	}
	var exports []string
	for _, sym := range syms {
		if IsExport(sym.Name, es) && ((elf.ST_BIND(sym.Info) == elf.STB_GLOBAL || elf.ST_BIND(sym.Info) == elf.STB_WEAK) && elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Section != elf.SHN_UNDEF) {
			if sym.Name == "_init" || sym.Name == "_fini" {
				// Musl inserts these symbols on shared libraries, but after we
				// compile the stub they will be linked internally, and should
				// not be exported.
				continue
			}
			exports = append(exports, sym.Name)
		}
	}
	ObjGetStackArgs(file, es)
	return exports
}

func DynamicGetExports(dynlib *os.File, es map[string]bool) ([]string, StackArgInfo) {
	f, err := elf.NewFile(dynlib)
	if err != nil {
		fatal(err)
	}
	return ObjGetExports(f, es), ObjGetStackArgs(f, es)
}

func StaticGetExports(staticlib *os.File, es map[string]bool) ([]string, StackArgInfo) {
	r, err := ar.NewReader(staticlib)
	if err != nil {
		fatal(err)
	}
	var exports []string
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

	fmt.Println(info)
	return info
}

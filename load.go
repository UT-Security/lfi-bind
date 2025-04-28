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
	"_lfi_stack_retfn",
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

var ignoredExports = map[string]bool{
	"_ZN2JS9GCCellPtr11checkedCastEPvNS_9TraceKindE": true,
	"_ZN2JS9GCCellPtrC2EDn": true,
	"_ZN2JS9GCCellPtrC2EP10JSFunction": true,
	"_ZN2JS9GCCellPtrC2EP8JSScript": true,
	"_ZN2JS9GCCellPtrC2EPvNS_9TraceKindE": true,
	"_ZN2JS9GCCellPtrC2Ev": true,
	"_ZN2JS9GCCellPtrC2I8JSObjectEEPT_": true,
	"_ZN2JS9GCCellPtrC2I8JSStringEEPT_": true,
	"_ZN2JS9GCCellPtrC2INS_6BigIntEEEPT_": true,
	"_ZN2JS9GCCellPtrC2INS_6SymbolEEEPT_": true,
	"_ZN2JS11PropertyKey10NonIntAtomEP6JSAtom": true,
	"_ZN2JS11PropertyKey10NonIntAtomEP8JSString": true,
	"_ZN2JS11PropertyKey11fromRawBitsEm": true,
	"_ZN2JS11PropertyKey3IntEi": true,
	"_ZN2JS11PropertyKey4VoidEv": true,
	"_ZN2JS11PropertyKey6SymbolEPNS_6SymbolE": true,
	"_ZN2JS11PropertyKey9fitsInIntEi": true,
	"_ZN2JS11PropertyKeyC2Ev": true,
	"_ZNK2JS11PropertyKey11toGCCellPtrEv": true,
	"_ZNK2JS11PropertyKey14toLinearStringEv": true,
	"_ZNK2JS11PropertyKey5isIntEv": true,
	"_ZNK2JS11PropertyKey5toIntEv": true,
	"_ZNK2JS11PropertyKey6isAtomEP6JSAtom": true,
	"_ZNK2JS11PropertyKey6isAtomEv": true,
	"_ZNK2JS11PropertyKey6isVoidEv": true,
	"_ZNK2JS11PropertyKey6toAtomEv": true,
	"_ZNK2JS11PropertyKey8isStringEv": true,
	"_ZNK2JS11PropertyKey8isSymbolEv": true,
	"_ZNK2JS11PropertyKey8toStringEv": true,
	"_ZNK2JS11PropertyKey8toSymbolEv": true,
	"_ZNK2JS11PropertyKey9asRawBitsEv": true,
	"_ZNK2JS11PropertyKey9isGCThingEv": true,
	"_ZNK2JS11PropertyKey9toGCThingEv": true,
	"_ZNK2JS11PropertyKeyeqERKS0_": true,
	"_ZNK2JS11PropertyKeyneERKS0_": true,
	"_ZNK2JS5Value11isPrimitiveEv": true,
	"_ZNK2JS5Value11isUndefinedEv": true,
	"_ZNK2JS5Value11magicUint32Ev": true,
	"_ZNK2JS5Value11toGCCellPtrEv": true,
	"_ZNK2JS5Value14isObjectOrNullEv": true,
	"_ZNK2JS5Value14toObjectOrNullEv": true,
	"_ZNK2JS5Value15toPrivateUint32Ev": true,
	"_ZNK2JS5Value16getObjectPayloadEv": true,
	"_ZNK2JS5Value16hasObjectPayloadEv": true,
	"_ZNK2JS5Value16isPrivateGCThingEv": true,
	"_ZNK2JS5Value17isNullOrUndefinedEv": true,
	"_ZNK2JS5Value19bitsAsPunboxPointerEv": true,
	"_ZNK2JS5Value20extractNonDoubleTypeEv": true,
	"_ZNK2JS5Value4typeEv": true,
	"_ZNK2JS5Value5toTagEv": true,
	"_ZNK2JS5Value6isNullEv": true,
	"_ZNK2JS5Value7isInt32Ei": true,
	"_ZNK2JS5Value7isInt32Ev": true,
	"_ZNK2JS5Value7isMagicE10JSWhyMagic": true,
	"_ZNK2JS5Value7isMagicEv": true,
	"_ZNK2JS5Value7toInt32Ev": true,
	"_ZNK2JS5Value8isBigIntEv": true,
	"_ZNK2JS5Value8isDoubleEv": true,
	"_ZNK2JS5Value8isNumberEv": true,
	"_ZNK2JS5Value8isObjectEv": true,
	"_ZNK2JS5Value8isStringEv": true,
	"_ZNK2JS5Value8isSymbolEv": true,
	"_ZNK2JS5Value8toBigIntEv": true,
	"_ZNK2JS5Value8toDoubleEv": true,
	"_ZNK2JS5Value8toNumberEv": true,
	"_ZNK2JS5Value8toObjectEv": true,
	"_ZNK2JS5Value8toStringEv": true,
	"_ZNK2JS5Value8toSymbolEv": true,
	"_ZNK2JS5Value8whyMagicEv": true,
	"_ZNK2JS5Value9asRawBitsEv": true,
	"_ZNK2JS5Value9isBooleanEv": true,
	"_ZNK2JS5Value9isGCThingEv": true,
	"_ZNK2JS5Value9isNumericEv": true,
	"_ZNK2JS5Value9toBooleanEv": true,
	"_ZNK2JS5Value9toGCThingEv": true,
	"_ZNK2JS5Value9toPrivateEv": true,
	"_ZNK2JS5Value9traceKindEv": true,
	"_ZNK2JS5ValueeqERKS0_": true,
	"_ZNK2JS5ValueneERKS0_": true,
	"_ZN2JS5Value10fromDoubleEd": true,
	"_ZN2JS5Value10setBooleanEb": true,
	"_ZN2JS5Value10setPrivateEPv": true,
	"_ZN2JS5Value11fromRawBitsEm": true,
	"_ZN2JS5Value12setUndefinedEv": true,
	"_ZN2JS5Value14bitsFromDoubleEd": true,
	"_ZN2JS5Value14setMagicUint32Ej": true,
	"_ZN2JS5Value15setObjectOrNullEP8JSObject": true,
	"_ZN2JS5Value16setObjectNoCheckEP8JSObject": true,
	"_ZN2JS5Value16setPrivateUint32Ej": true,
	"_ZN2JS5Value17fromTagAndPayloadE10JSValueTagm": true,
	"_ZN2JS5Value17setPrivateGCThingEPN2js2gc4CellE": true,
	"_ZN2JS5Value21bitsFromTagAndPayloadE10JSValueTagm": true,
	"_ZN2JS5Value21isNumberRepresentableIiEEbT_": true,
	"_ZN2JS5Value21isNumberRepresentableImEEbT_": true,
	"_ZN2JS5Value4swapERS0_": true,
	"_ZN2JS5Value7setNullEv": true,
	"_ZN2JS5Value8setInt32Ei": true,
	"_ZN2JS5Value8setMagicE10JSWhyMagic": true,
	"_ZN2JS5Value9fromInt32Ei": true,
	"_ZN2JS5Value9setBigIntEPNS_6BigIntE": true,
	"_ZN2JS5Value9setDoubleEd": true,
	"_ZN2JS5Value9setNumberEd": true,
	"_ZN2JS5Value9setNumberIiEEvT_": true,
	"_ZN2JS5Value9setNumberImEEvT_": true,
	"_ZN2JS5Value9setObjectER8JSObject": true,
	"_ZN2JS5Value9setStringEP8JSString": true,
	"_ZN2JS5Value9setSymbolEPNS_6SymbolE": true,
	"_ZN2JS5ValueC2Em": true,
	"_ZN2JS5ValueC2Ev": true,
	"_ZN2JS18InstantiateOptionsC2ERKNS_22ReadOnlyCompileOptionsE": true,
	"_ZNK2JS18InstantiateOptions24hideFromNewScriptInitialEv": true,
	"_ZNK2JS18InstantiateOptions6copyToERNS_14CompileOptionsE": true,
	"_ZN2js15TempAllocPolicyC2EP9JSContext": true,
	"_ZNK2JS9GCCellPtr15unsafeAsUIntPtrEv": true,
	"_ZNK2JS9GCCellPtr24mayBeOwnedByOtherRuntimeEv": true,
	"_ZNK2JS9GCCellPtr2asI8JSObjectvEERT_v": true,
	"_ZNK2JS9GCCellPtr2asI8JSStringvEERT_v": true,
	"_ZNK2JS9GCCellPtr2asINS_6BigIntEvEERT_v": true,
	"_ZNK2JS9GCCellPtr2asINS_6SymbolEvEERT_v": true,
	"_ZNK2JS9GCCellPtr2isI8JSObjectvEEbv": true,
	"_ZNK2JS9GCCellPtr2isI8JSStringvEEbv": true,
	"_ZNK2JS9GCCellPtr2isINS_6BigIntEvEEbv": true,
	"_ZNK2JS9GCCellPtr2isINS_6SymbolEvEEbv": true,
	"_ZNK2JS9GCCellPtr4kindEv": true,
	"_ZNK2JS9GCCellPtr6asCellEv": true,
	"_ZNK2JS9GCCellPtrcvbEv": true,
	"_ZN2JS12AutoFilenameC2Ev": true,
	"_ZN2JS12AutoFilenameD2Ev": true,
	"_ZN2JS18PropertyDescriptor11setWritableEb": true,
	"_ZN2JS18PropertyDescriptor12setResolvingEb": true,
	"_ZN2JS18PropertyDescriptor13setEnumerableEb": true,
	"_ZN2JS18PropertyDescriptor13valueDoNotUseEv": true,
	"_ZN2JS18PropertyDescriptor14getterDoNotUseEv": true,
	"_ZN2JS18PropertyDescriptor14setterDoNotUseEv": true,
	"_ZN2JS18PropertyDescriptor15setConfigurableEb": true,
	"_ZN2JS18PropertyDescriptor4DataERKNS_5ValueEj": true,
	"_ZN2JS18PropertyDescriptor4DataERKNS_5ValueENS_18PropertyAttributesE": true,
	"_ZN2JS18PropertyDescriptor5EmptyEv": true,
	"_ZN2JS18PropertyDescriptor8AccessorEN7mozilla5MaybeIP8JSObjectEES5_j": true,
	"_ZN2JS18PropertyDescriptor8AccessorEP8JSObjectS2_NS_18PropertyAttributesE": true,
	"_ZN2JS18PropertyDescriptor8setValueERKNS_5ValueE": true,
	"_ZN2JS18PropertyDescriptor9setGetterEP8JSObject": true,
	"_ZN2JS18PropertyDescriptor9setSetterEP8JSObject": true,
	"_ZN2JS18PropertyDescriptorC2Ev": true,
	"_ZNK2JS18PropertyDescriptor10enumerableEv": true,
	"_ZNK2JS18PropertyDescriptor11assertValidEv": true,
	"_ZNK2JS18PropertyDescriptor11hasWritableEv": true,
	"_ZNK2JS18PropertyDescriptor12configurableEv": true,
	"_ZNK2JS18PropertyDescriptor13hasEnumerableEv": true,
	"_ZNK2JS18PropertyDescriptor13valueDoNotUseEv": true,
	"_ZNK2JS18PropertyDescriptor14assertCompleteEv": true,
	"_ZNK2JS18PropertyDescriptor14getterDoNotUseEv": true,
	"_ZNK2JS18PropertyDescriptor14setterDoNotUseEv": true,
	"_ZNK2JS18PropertyDescriptor15hasConfigurableEv": true,
	"_ZNK2JS18PropertyDescriptor16isDataDescriptorEv": true,
	"_ZNK2JS18PropertyDescriptor19isGenericDescriptorEv": true,
	"_ZNK2JS18PropertyDescriptor20isAccessorDescriptorEv": true,
	"_ZNK2JS18PropertyDescriptor5valueEv": true,
	"_ZNK2JS18PropertyDescriptor6getterEv": true,
	"_ZNK2JS18PropertyDescriptor6setterEv": true,
	"_ZNK2JS18PropertyDescriptor8hasValueEv": true,
	"_ZNK2JS18PropertyDescriptor8writableEv": true,
	"_ZNK2JS18PropertyDescriptor9hasGetterEv": true,
	"_ZNK2JS18PropertyDescriptor9hasSetterEv": true,
	"_ZNK2JS18PropertyDescriptor9resolvingEv": true,
}

func IsExport(sym string, exports map[string]bool) bool {
	dsym := demangle.Filter(sym)
	_, after, found := strings.Cut(dsym, " ")

	if ignoredExports[sym] {
		return false
	}

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

package qjs

import (
	"errors"
	"math"
)

// Context is a QuickJS execution context bound to a Runtime.
type Context struct {
	rt     *Runtime
	handle uint64 // JSContext*
	global *Value
	// Cached intrinsics, resolved on first use and retained for the realm's life.
	// isByteArray/classTag run on every JS→Go bulk transfer, so re-resolving them per call
	// was needless churn on a hot path.
	objToString *Value // Object.prototype.toString, for classTag
	abCtor      *Value // the ArrayBuffer constructor, for isByteArray's instanceof
}

// Value wraps a NaN-boxed JSValue (uint64) plus its context.
type Value struct {
	c   *Context
	raw uint64
}

// This is the receiver passed to a Go callback: the JS `this` plus the call args.
type This struct {
	*Value
	context *Context
	args    []*Value
}

func (c *Context) value(raw uint64) *Value { return &Value{c: c, raw: raw} }

// call dispatches a wasm export and wraps the i64 result as a *Value.
func (c *Context) callV(name string, args ...uint64) *Value {
	return c.value(c.rt.call(name, args...))
}

func (v *Value) Raw() uint64 {
	if v == nil {
		return 0
	}
	return v.raw
}

// Context returns the value's owning context.
func (v *Value) Context() *Context { return v.c }

// Free releases the JSValue reference.
func (v *Value) Free() {
	if v != nil && v.raw != 0 {
		// A closed runtime has had its linear memory reclaimed by wazero, so there is
		// nothing to free and the call would panic. A killed call path is full of deferred
		// Free()s, and they must not turn a clean error into a panic.
		if !v.c.rt.Alive() {
			v.raw = 0
			return
		}
		v.c.rt.call("QJS_FreeValue", v.c.handle, v.raw)
		v.raw = 0
	}
}

// Dup retains an extra reference (QJS_CloneValue == JS_DupValue), so a JS value handed to
// a host callback can outlive that synchronous call — the event loop holds JS callbacks
// this way. The returned *Value must be Free()d once.
func (v *Value) Dup() *Value {
	if v == nil || v.raw == 0 {
		return nil
	}
	return v.c.callV("QJS_CloneValue", v.c.handle, v.raw)
}

func (t *This) Context() *Context { return t.context }
func (t *This) Args() []*Value    { return t.args }

// ── Context constructors ──────────────────────────────────────────────────────

func (c *Context) Global() *Value {
	if c.global == nil {
		c.global = c.callV("JS_GetGlobalObject", c.handle)
	}
	return c.global
}

func (c *Context) NewObject() *Value    { return c.callV("JS_NewObject", c.handle) }
func (c *Context) NewNull() *Value      { return c.callV("JS_NewNull") }
func (c *Context) NewUndefined() *Value { return c.callV("JS_NewUndefined") }

func (c *Context) NewBool(b bool) *Value {
	n := uint64(0)
	if b {
		n = 1
	}
	return c.callV("QJS_NewBool", c.handle, n)
}

func (c *Context) NewInt32(v int32) *Value {
	return c.callV("QJS_NewInt32", c.handle, uint64(uint32(v)))
}
func (c *Context) NewInt64(v int64) *Value { return c.callV("QJS_NewInt64", c.handle, uint64(v)) }

// NewFloat64 makes a JS number carrying the full double. The shim takes the bits rather
// than an f64 so the flat QJS_* ABI stays integer-only across the wasm boundary.
func (c *Context) NewFloat64(v float64) *Value {
	return c.callV("QJS_NewFloat64", c.handle, math.Float64bits(v))
}

func (c *Context) NewString(s string) *Value {
	ptr := c.rt.writeCStr(s)
	defer c.rt.freeAt(ptr) // QJS_NewString copies into a JS string
	return c.callV("QJS_NewString", c.handle, ptr)
}

// NewArrayBuffer creates a JS ArrayBuffer copy of b, staging the bytes straight into one
// wasm buffer so the payload is walked once before QJS_NewArrayBufferCopy takes it.
func (c *Context) NewArrayBuffer(b []byte) *Value {
	if len(b) == 0 {
		return c.callV("QJS_NewArrayBufferCopy", c.handle, 0, 0)
	}
	ptr := c.rt.mallocN(len(b))
	defer c.rt.freeAt(ptr)
	c.rt.mem.Write(uint32(ptr), b)
	return c.callV("QJS_NewArrayBufferCopy", c.handle, ptr, uint64(len(b)))
}

// Function wraps a Go func as a JS function. The callback id is registered and
// baked into the proxy via QJS_CreateFunctionProxy; ctxID/isAsync are unused
// (single context, synchronous only).
func (c *Context) Function(fn goFunc) *Value {
	id := c.rt.reg.register(fn)
	return c.callV("QJS_CreateFunctionProxy", c.handle, id, 0, 0)
}

// ── Value properties / conversions ────────────────────────────────────────────

func (v *Value) SetPropertyStr(name string, val *Value) {
	if val == nil {
		return
	}
	ptr := v.c.rt.writeCStr(name)
	defer v.c.rt.freeAt(ptr) // JS_SetPropertyStr interns the name, does not own it
	v.c.rt.call("JS_SetPropertyStr", v.c.handle, v.raw, ptr, val.raw)
}

func (v *Value) GetPropertyStr(name string) *Value {
	ptr := v.c.rt.writeCStr(name)
	defer v.c.rt.freeAt(ptr)
	return v.c.callV("JS_GetPropertyStr", v.c.handle, v.raw, ptr)
}

// String renders the value as a string (QJS_ToCString).
func (v *Value) String() string {
	return v.c.rt.readPackedString(v.c.rt.call("QJS_ToCString", v.c.handle, v.raw))
}

func (v *Value) Int64() int64 {
	return int64(v.c.rt.call("QJS_ToInt64", v.c.handle, v.raw))
}

func (v *Value) Int32() int32 {
	return int32(uint32(v.c.rt.call("QJS_ToInt32", v.c.handle, v.raw)))
}

func (v *Value) boolCall(name string, args ...uint64) bool {
	return int32(v.c.rt.call(name, args...)) != 0
}

func (v *Value) IsUndefined() bool { return v.boolCall("QJS_IsUndefined", v.raw) }
func (v *Value) IsNull() bool      { return v.boolCall("QJS_IsNull", v.raw) }
func (v *Value) IsObject() bool    { return v.boolCall("QJS_IsObject", v.raw) }

// isByteArray reports whether v is an ArrayBuffer — a bare buffer toByteArray can read
// directly. A typed-array/DataView view is NOT one (JsTypedArrayToGo reads those via their
// .buffer), so this returns false for them.
//
// The brand check must use classTag (Object.prototype.toString.call), NOT v.String():
// String() is the value's *own* toString, which for a TypedArray is Array's join and
// serializes every element. Probing a 64 KB Uint8Array that way built a ~200 KB string per
// call and made every JS→Go bulk transfer O(payload) with a huge constant — ~12 ms for a
// 64 KB block, vs ~80 µs the other direction. The class tag is O(1) and contents-blind.
func (v *Value) isByteArray() bool {
	if !v.IsObject() {
		return false // a primitive is never an ArrayBuffer
	}
	// instanceof first (same-realm, the common case); the class-tag fallback catches a
	// cross-realm ArrayBuffer, for which instanceof against this realm's ctor fails.
	if ctor := v.c.arrayBufferCtor(); ctor != nil &&
		v.boolCall("QJS_IsInstanceOf", v.c.handle, v.raw, ctor.raw) {
		return true
	}
	return v.classTag() == "[object ArrayBuffer]"
}

// arrayBufferCtor returns the realm's ArrayBuffer constructor, cached after first use, or
// nil if the realm has no ArrayBuffer global — in which case isByteArray falls back to the
// class tag.
func (c *Context) arrayBufferCtor() *Value {
	if c.abCtor == nil {
		ctor := c.Global().GetPropertyStr("ArrayBuffer")
		if ctor.IsUndefined() {
			ctor.Free()
			return nil
		}
		c.abCtor = ctor
	}
	return c.abCtor
}

// classTag returns v's brand via Object.prototype.toString.call(v) — e.g. "[object
// ArrayBuffer]". Unlike String() it ignores the value's own toString, so it is O(1)
// regardless of contents (see isByteArray).
func (v *Value) classTag() string {
	r, err := v.c.Invoke(v.c.objectToString(), v) // Object.prototype.toString.call(v)
	if err != nil {
		return ""
	}
	defer r.Free()
	return r.String()
}

// objectToString returns Object.prototype.toString, cached after first use.
func (c *Context) objectToString() *Value {
	if c.objToString == nil {
		obj := c.Global().GetPropertyStr("Object")
		defer obj.Free()
		proto := obj.GetPropertyStr("prototype")
		defer proto.Free()
		c.objToString = proto.GetPropertyStr("toString")
	}
	return c.objToString
}

// toByteArray returns a copy of the ArrayBuffer's bytes, leaving the source intact.
//
// QJS_GetArrayBuffer returns a pointer to the buffer's *live* storage plus a freshly
// malloc'd packed cell, so the cell is the only thing this owns to free. Freeing `addr`
// instead detaches the source ArrayBuffer out from under QuickJS — harmless when a value
// is read once and dropped, a use-after-free when it is reused (a node identity's
// privateKey signed against more than one peer, any retained Uint8Array read twice).
func (v *Value) toByteArray() []byte {
	packed := v.c.rt.call("QJS_GetArrayBuffer", v.c.handle, v.raw)
	if packed == 0 {
		return nil
	}
	addr, size := v.c.rt.unpackPtr(packed)
	var out []byte
	if addr != 0 && size != 0 {
		buf, _ := v.c.rt.mem.Read(addr, size)
		out = make([]byte, size)
		copy(out, buf)
	}
	v.c.rt.freeAt(packed) // the malloc'd cell only — addr is the live buffer, owned by JS
	return out
}

// byteArrayLength reads an ArrayBuffer's live size without copying its contents. As with
// toByteArray, QJS_GetArrayBuffer's packed cell is the only allocation this owns.
func (v *Value) byteArrayLength() (int64, error) {
	packed := v.c.rt.call("QJS_GetArrayBuffer", v.c.handle, v.raw)
	if packed == 0 {
		return 0, errors.New("qjs: value is not a byte array")
	}
	_, size := v.c.rt.unpackPtr(packed)
	v.c.rt.freeAt(packed)
	return int64(size), nil
}

// toByteArrayWindow copies just the [offset, offset+length) window, with the same
// ownership story as toByteArray. The window is validated against the buffer size QuickJS
// itself reports — never the caller's numbers alone — so a forged byteOffset/byteLength
// cannot read past the buffer. O(window), so a small view over a large buffer neither
// copies nor pins the whole backing store.
func (v *Value) toByteArrayWindow(offset, length int64) ([]byte, error) {
	packed := v.c.rt.call("QJS_GetArrayBuffer", v.c.handle, v.raw)
	if packed == 0 {
		return nil, errors.New("qjs: value is not a byte array")
	}
	addr, size := v.c.rt.unpackPtr(packed)
	v.c.rt.freeAt(packed) // the malloc'd cell only — addr is the live buffer, owned by JS
	// Compare by subtraction, not addition: offset and length arrive from JS getters, and a
	// hostile pair near 2^62 would overflow offset+length.
	if offset < 0 || length < 0 || offset > int64(size) || length > int64(size)-offset {
		return nil, errors.New("qjs: typed array view out of range")
	}
	out := make([]byte, length)
	if length > 0 {
		buf, ok := v.c.rt.mem.Read(addr+uint32(offset), uint32(length))
		if !ok {
			return nil, errors.New("qjs: buffer window outside wasm memory")
		}
		copy(out, buf)
	}
	return out, nil
}

// exception turns an error/exception value into a Go error (message + stack).
func (v *Value) exception() error {
	cause := v.String()
	stack := v.GetPropertyStr("stack")
	defer stack.Free()
	if stack.IsUndefined() {
		return errors.New(cause)
	}
	return errors.New(cause + "\n" + stack.String())
}

func (c *Context) hasException() bool {
	return int32(c.rt.call("JS_HasException", c.handle)) != 0
}

func (c *Context) exception() error {
	val := c.callV("JS_GetException", c.handle)
	defer val.Free()
	return val.exception()
}

func (c *Context) throwError(err error) uint64 {
	msg := c.NewString(err.Error())
	errVal := c.callV("JS_NewError", c.handle)
	errVal.SetPropertyStr("message", msg)
	return c.rt.call("JS_Throw", c.handle, errVal.raw)
}

// ── invoke ────────────────────────────────────────────────────────────────────

// Invoke calls fn with the given this and args, returning its result or a JS error.
func (c *Context) Invoke(fn, this *Value, args ...*Value) (*Value, error) {
	argc, argvPtr := c.marshalArgs(args...)
	if argvPtr != 0 {
		defer c.rt.freeAt(argvPtr)
	}
	res := c.callV("QJS_Call", c.handle, fn.raw, this.raw, argc, argvPtr)
	return c.normalize(res)
}

// marshalArgs writes the JSValue args contiguously into wasm memory, straight into the
// malloc'd region rather than through a Go-side staging slice — this runs on every Invoke.
func (c *Context) marshalArgs(args ...*Value) (uint64, uint64) {
	if len(args) == 0 {
		return 0, 0
	}
	ptr := c.rt.mallocN(8 * len(args))
	for i, a := range args {
		c.rt.mem.WriteUint64Le(uint32(ptr)+uint32(i*8), a.raw)
	}
	return uint64(len(args)), ptr
}

// normalize converts a pending JS exception into a Go error. The context's exception flag
// is the only failure signal: an Error *value* is deliberately not one, since a JS function
// may legitimately return an Error as data, which must round-trip.
func (c *Context) normalize(v *Value) (*Value, error) {
	if c.hasException() {
		v.Free()
		return nil, c.exception()
	}
	return v, nil
}

// ── eval ──────────────────────────────────────────────────────────────────────

// EvalOptionFunc configures an Eval call.
type EvalOptionFunc func(*evalOptions)

type evalOptions struct {
	code  string
	flags uint64
}

// Code sets the JS source to evaluate.
func Code(src string) EvalOptionFunc {
	return func(o *evalOptions) { o.code = src }
}

// Eval evaluates JS source (provided via Code) under the given filename.
func (c *Context) Eval(file string, opts ...EvalOptionFunc) (*Value, error) {
	o := &evalOptions{flags: evalTypeGlobal | evalFlagStrict}
	for _, fn := range opts {
		fn(o)
	}

	filePtr := c.rt.writeCStr(file)
	codePtr := uint64(0)
	if o.code != "" {
		codePtr = c.rt.writeCStr(o.code)
	}
	// QJS_CreateEvalOption(codeBuf, bytecodeBuf, bytecodeLen, filename, flags)
	optPtr := c.rt.call("QJS_CreateEvalOption", codePtr, 0, 0, filePtr, o.flags)
	res := c.callV("QJS_Eval", c.handle, optPtr)
	// The eval buffers had to outlive QJS_Eval; free them now.
	if codePtr != 0 {
		c.rt.freeAt(codePtr)
	}
	c.rt.freeAt(filePtr)
	c.rt.freeAt(optPtr) // the option cell QJS_CreateEvalOption malloc'd; QJS_Eval does not free it
	return c.normalize(res)
}

// Pump runs the QuickJS job queue (microtasks and settled-promise reactions) to
// completion, and reports whether a job left an exception standing. The loader supplies
// Go-backed timers, so there are no os timers to wait on and this returns as soon as the
// queue is empty. The event loop calls it after every re-entry into JS so promise chains
// advance, and guest.go calls it once per invocation and per settlement to keep the causal
// clock on the stack — a path hot enough that the drain is called directly rather than as
// QJS_Eval's trailing side effect, which had to compile and run an expression first.
// Verified by TestQjsPumpModel.
func (c *Context) Pump() error {
	// js_std_loop answers JS_HasException: an int, so the same narrowing every other
	// predicate export gets before it is read as a flag.
	if int32(c.rt.call("js_std_loop", c.handle)) == 0 {
		return nil
	}
	return c.exception()
}

// JsTypedArrayToGo returns the bytes of a TypedArray/DataView/ArrayBuffer as an
// independent Go copy. The source is NOT detached, so the same value (a shared singleton,
// a node key signed against many peers) can be read any number of times, and callers never
// need a defensive .slice() before handing a typed array across this seam. For a view it
// returns only that view's window, copying O(view) rather than the backing buffer.
func JsTypedArrayToGo(input *Value) ([]byte, error) {
	// Reject non-objects up front: GetPropertyStr("buffer") below would throw a TypeError
	// on null/undefined/a primitive and leave the exception flag set, poisoning the next
	// unrelated JS call (and a nil *Value would panic here).
	if input == nil || !input.IsObject() {
		return nil, errors.New("qjs: expected a typed array or ArrayBuffer")
	}
	if input.isByteArray() {
		return input.toByteArray(), nil
	}
	buffer := input.GetPropertyStr("buffer")
	defer buffer.Free()
	if buffer.IsUndefined() || buffer.IsNull() {
		return nil, errors.New("qjs: value has no ArrayBuffer backing")
	}
	if !buffer.isByteArray() {
		return nil, errors.New("qjs: value is not a byte array")
	}
	offset := input.GetPropertyStr("byteOffset").Int64()
	length := input.GetPropertyStr("byteLength").Int64()
	return buffer.toByteArrayWindow(offset, length)
}

// JsTypedArrayByteLength validates the same TypedArray/DataView/ArrayBuffer shapes as
// JsTypedArrayToGo and returns the view width without making the payload-sized Go copy.
// Resource gates use it before crossing that copy boundary.
func JsTypedArrayByteLength(input *Value) (int64, error) {
	if input == nil || !input.IsObject() {
		return 0, errors.New("qjs: expected a typed array or ArrayBuffer")
	}
	if input.isByteArray() {
		return input.byteArrayLength()
	}
	buffer := input.GetPropertyStr("buffer")
	defer buffer.Free()
	if buffer.IsUndefined() || buffer.IsNull() {
		return 0, errors.New("qjs: value has no ArrayBuffer backing")
	}
	if !buffer.isByteArray() {
		return 0, errors.New("qjs: value is not a byte array")
	}
	offset := input.GetPropertyStr("byteOffset").Int64()
	length := input.GetPropertyStr("byteLength").Int64()
	bufferLength, err := buffer.byteArrayLength()
	if err != nil {
		return 0, err
	}
	if offset < 0 || length < 0 || offset > bufferLength || length > bufferLength-offset {
		return 0, errors.New("qjs: typed array view out of range")
	}
	return length, nil
}

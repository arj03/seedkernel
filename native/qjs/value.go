package qjs

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

// Context is a QuickJS execution context bound to a Runtime.
type Context struct {
	rt     *Runtime
	handle uint64 // JSContext*
	global *Value
}

// Value wraps a NaN-boxed JSValue (uint64) plus its context.
type Value struct {
	c   *Context
	raw uint64
}

func (c *Context) value(raw uint64) *Value { return &Value{c: c, raw: raw} }

// callV dispatches a wasm export and wraps the i64 result as a *Value.
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

// Dup retains an extra reference, so a JS value handed to a host callback can outlive that
// synchronous call — the event loop holds JS callbacks this way. The returned *Value must
// be Free()d once.
func (v *Value) Dup() *Value {
	if v == nil || v.raw == 0 {
		return nil
	}
	return v.c.callV("QJS_DupValue", v.c.handle, v.raw)
}

// ── Context constructors ──────────────────────────────────────────────────────

func (c *Context) Global() *Value {
	if c.global == nil {
		c.global = c.callV("JS_GetGlobalObject", c.handle)
	}
	return c.global
}

func (c *Context) NewObject() *Value    { return c.callV("JS_NewObject", c.handle) }
func (c *Context) NewNull() *Value      { return c.callV("QJS_Null") }
func (c *Context) NewUndefined() *Value { return c.callV("QJS_Undefined") }

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

// NewString makes a JS string from s, which crosses with its length: a NUL inside it is a
// character like any other.
func (c *Context) NewString(s string) *Value {
	ptr := c.rt.writeCStr(s)
	defer c.rt.freeAt(ptr) // QJS_NewString copies into a JS string
	return c.callV("QJS_NewString", c.handle, ptr, uint64(len(s)))
}

// NewArrayBuffer creates a JS ArrayBuffer holding a copy of b, written straight into the
// buffer's own storage. When the engine cannot allocate it, the result is the engine's
// exception value, with the out-of-memory error left pending for the caller's next check.
func (c *Context) NewArrayBuffer(b []byte) *Value {
	v := c.callV("QJS_NewArrayBuffer", c.handle, uint64(len(b)))
	if len(b) > 0 {
		if addr, _, ok := v.window(); ok {
			c.rt.mem.Write(addr, b)
		}
	}
	return v
}

// Function wraps a Go func as a JS function: an engine function carrying the Go func's
// index in the runtime's funcs, which env.callGo resolves.
func (c *Context) Function(fn goFunc) *Value {
	id := len(c.rt.funcs)
	c.rt.funcs = append(c.rt.funcs, fn)
	return c.callV("QJS_NewFunction", c.handle, uint64(id))
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

// String renders the value as a string, "" when the conversion throws — and the throw is
// TAKEN by the shim rather than left pending, so a value nothing can convert (a Symbol, a
// throwing toString) cannot surface as the failure of the next, unrelated call on this
// context. Int64 and Int32 answer 0 the same way. All three are reached with arguments a
// guest chose (guest.go's __host_call), so the clean-context invariant is not the caller's
// to keep.
func (v *Value) String() string {
	return v.c.rt.readString(v.c.rt.call("QJS_ToCString", v.c.handle, v.raw))
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

// ── bytes ─────────────────────────────────────────────────────────────────────

// window resolves an ArrayBuffer or a TypedArray to the storage it covers (QJS_GetBytes).
// ok=false leaves the engine's TypeError pending. The window is live memory, valid only
// until JS next runs.
func (v *Value) window() (addr, size uint32, ok bool) {
	packed := v.c.rt.call("QJS_GetBytes", v.c.handle, v.raw)
	if packed == math.MaxUint64 {
		return 0, 0, false
	}
	return uint32(packed >> 32), uint32(packed), true
}

// Bytes returns the bytes of an ArrayBuffer or a TypedArray as an independent Go copy —
// for a view, just its window. The shape comes from the engine's own slots, never from
// properties, so no JS runs and nothing a caller defined on the object is believed;
// anything else (a DataView, an object that only looks like a view, a detached buffer) is
// refused, and the engine's error is taken so the next call does not inherit it. The value
// is left intact, so it can be read any number of times.
func (v *Value) Bytes() ([]byte, error) {
	addr, size, ok := v.window()
	if !ok {
		return nil, notBytes(v.c)
	}
	out := make([]byte, size)
	if size > 0 {
		buf, ok := v.c.rt.mem.Read(addr, size)
		if !ok {
			return nil, errors.New("qjs: byte window outside wasm memory")
		}
		copy(out, buf)
	}
	return out, nil
}

// ByteLength answers the width Bytes would copy, without copying it: resource gates admit
// against it before the copy.
func (v *Value) ByteLength() (int64, error) {
	_, size, ok := v.window()
	if !ok {
		return 0, notBytes(v.c)
	}
	return int64(size), nil
}

func notBytes(c *Context) error {
	return fmt.Errorf("qjs: expected an ArrayBuffer or a TypedArray: %w", c.exception())
}

// ── errors ────────────────────────────────────────────────────────────────────

// asError renders a thrown or rejected value as a Go error: its string form, plus its stack
// when it has one. Only an object is asked for a stack — reading a property of undefined or
// null would itself throw, and leave that exception for the next call to inherit.
func (v *Value) asError() error {
	cause := v.String()
	if !v.IsObject() {
		return errors.New(cause)
	}
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

// exception takes the pending exception, clearing it, as a Go error.
func (c *Context) exception() error {
	val := c.callV("JS_GetException", c.handle)
	defer val.Free()
	return val.asError()
}

// throwError throws err into JS as a plain Error, returning the engine's exception value
// for a callback to answer with.
func (c *Context) throwError(err error) uint64 {
	msg := err.Error()
	ptr := c.rt.writeCStr(msg)
	defer c.rt.freeAt(ptr)
	return c.rt.call("QJS_ThrowError", c.handle, ptr, uint64(len(msg)))
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

// Eval evaluates src as strict global code under the given filename, and answers its
// completion value as it stands: a promise is returned, not awaited, and the jobs the code
// queued wait for Pump.
func (c *Context) Eval(file, src string) (*Value, error) {
	filePtr := c.rt.writeCStr(file)
	defer c.rt.freeAt(filePtr)
	// NUL-terminated because JS_Eval requires it, with the length passed alongside, so a
	// NUL inside the source is source like any other byte.
	codePtr := c.rt.writeCStr(src)
	defer c.rt.freeAt(codePtr)
	return c.normalize(c.callV("QJS_Eval", c.handle, codePtr, uint64(len(src)), filePtr))
}

// Pump runs the job queue (microtasks and settled-promise reactions) to completion and
// reports what went wrong on the way: a job that threw, or — for a runtime made with
// TrackRejections — the promises still rejected with no handler once the queue is empty.
// The loader supplies Go-backed timers, so there is nothing to wait on and this returns as
// soon as the queue is empty. The event loop calls it after every re-entry into JS so
// promise chains advance, and guest.go calls it once per invocation and per settlement to
// keep the causal clock on the stack. Verified by TestQjsPumpModel.
func (c *Context) Pump() error {
	n := int32(c.rt.call("QJS_RunJobs", c.handle))
	if n == 0 {
		return nil
	}
	if n < 0 {
		return c.exception()
	}
	reasons := make([]string, n)
	for i := range reasons {
		reason := c.callV("QJS_TakeRejection", c.handle)
		reasons[i] = reason.asError().Error()
		reason.Free()
	}
	return errors.New("unhandled promise rejection: " + strings.Join(reasons, "; "))
}

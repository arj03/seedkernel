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
	if v == nil || v.raw == 0 {
		return
	}
	// Immediates hold no reference, and a closed runtime has nothing left to free.
	if !v.IsUndefined() && !v.IsNull() && v.c.rt.Alive() {
		v.c.rt.call("QJS_FreeValue", v.c.handle, v.raw)
	}
	v.raw = 0
}

// Dup retains an extra reference, so a value can outlive the call that handed it over.
// Free the result once.
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
func (c *Context) NewNull() *Value      { return c.value(c.rt.null) }
func (c *Context) NewUndefined() *Value { return c.value(c.rt.undefined) }

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

// NewFloat64 makes a JS number; it crosses as bits, keeping the ABI integer-only.
func (c *Context) NewFloat64(v float64) *Value {
	return c.callV("QJS_NewFloat64", c.handle, math.Float64bits(v))
}

// NewString makes a JS string from s; it crosses with its length, so NULs survive.
func (c *Context) NewString(s string) *Value {
	ptr := c.rt.writeCStr(s)
	defer c.rt.freeAt(ptr)
	return c.callV("QJS_NewString", c.handle, ptr, uint64(len(s)))
}

// NewArrayBuffer creates a JS ArrayBuffer holding a copy of b. On allocation failure it
// returns the exception value with the error left pending.
func (c *Context) NewArrayBuffer(b []byte) *Value {
	v := c.callV("QJS_NewArrayBuffer", c.handle, uint64(len(b)))
	if len(b) > 0 {
		if addr, _, ok := v.window(); ok {
			c.rt.mem.Write(addr, b)
		}
	}
	return v
}

// Function wraps a Go func as a JS function, dispatched through env.callGo.
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
	defer v.c.rt.freeAt(ptr)
	v.c.rt.call("JS_SetPropertyStr", v.c.handle, v.raw, ptr, val.raw)
}

func (v *Value) GetPropertyStr(name string) *Value {
	ptr := v.c.rt.writeCStr(name)
	defer v.c.rt.freeAt(ptr)
	return v.c.callV("JS_GetPropertyStr", v.c.handle, v.raw, ptr)
}

// String renders the value as a string, or "" if the conversion throws; the shim clears
// the exception so it cannot fail the next call. Int64 and Int32 answer 0 the same way.
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

// IsUndefined and IsNull compare the tag in a NaN-boxed JSValue's high word.
func (v *Value) IsUndefined() bool { return v.raw>>32 == v.c.rt.undefined>>32 }
func (v *Value) IsNull() bool      { return v.raw>>32 == v.c.rt.null>>32 }
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

// Bytes copies out the bytes of an ArrayBuffer or TypedArray. The shape comes from the
// engine's internal slots, so no JS runs; anything else is refused and the error cleared.
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

// View borrows the bytes of an ArrayBuffer or TypedArray without copying. It is valid
// only until this runtime next runs, since any engine call may grow its memory: read
// every other argument first, take the view last, and hand it to something outside this
// runtime before returning. Anything that must outlive that takes Bytes().
func (v *Value) View() ([]byte, error) {
	addr, size, ok := v.window()
	if !ok {
		return nil, notBytes(v.c)
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf, ok := v.c.rt.mem.Read(addr, size)
	if !ok {
		return nil, errors.New("qjs: byte window outside wasm memory")
	}
	return buf, nil
}

// ByteLength returns the width Bytes would copy, without copying.
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

// asError renders a thrown value as a Go error, with its stack if it is an object that
// has one.
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

// marshalArgs writes the args contiguously into wasm memory.
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

// normalize converts a pending exception into a Go error. A returned Error value is data,
// not a failure.
func (c *Context) normalize(v *Value) (*Value, error) {
	if c.hasException() {
		v.Free()
		return nil, c.exception()
	}
	return v, nil
}

// ── eval ──────────────────────────────────────────────────────────────────────

// Eval evaluates src as strict global code and returns its completion value unawaited;
// queued jobs wait for Pump.
func (c *Context) Eval(file, src string) (*Value, error) {
	filePtr := c.rt.writeCStr(file)
	defer c.rt.freeAt(filePtr)
	// NUL-terminated for JS_Eval, with the length alongside.
	codePtr := c.rt.writeCStr(src)
	defer c.rt.freeAt(codePtr)
	return c.normalize(c.callV("QJS_Eval", c.handle, codePtr, uint64(len(src)), filePtr))
}

// Pump runs the job queue to completion and reports a job that threw, or, with
// TrackRejections, the rejections left unhandled. It never waits.
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

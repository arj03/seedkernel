/* The flat ABI the Go bridge (../qjs.go, ../value.go) drives quickjs-ng through.

   Every JSValue crosses as one i64 — this build is NaN-boxed — and every pointer as an i32,
   so each export is a plain wasm function Go calls without marshaling. A result that is an
   address and a length packs both into one i64, (addr << 32) | len, so reading one costs a
   single call and no allocation.

   Nothing else is linked in: no quickjs-libc, no module loader, no filesystem. A runtime is
   the engine's ECMAScript intrinsics plus whatever Go installs on it, which is what keeps a
   guest realm zero-authority — there is no host object for it to reach, and no module name
   that resolves. The engine's WASI imports are Go's to answer (qjs.go instantiateWASI). */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <quickjs.h>
#include <cutils.h> /* js__hrtime_ns: the engine's own monotonic clock */

/* The one host import: a JS call to the Go function registered under `id`. */
__attribute__((import_module("env"), import_name("callGo")))
extern JSValue qjs_call_go(JSContext *ctx, JSValueConst this_val, int argc,
                           JSValueConst *argv, uint32_t id);

/* ── execution deadline ──────────────────────────────────────────────────────
   QuickJS's own interrupt lever, wired to a monotonic deadline: one clock read per ~100k
   bytecodes, and an overrun surfaces as an ordinary catchable exception, so a runtime
   survives its own budget kill.

   The deadline is absolute (js__hrtime_ns), set through QJS_SetDeadline so the embedder
   never shares a clock origin with the module: it passes a duration, and the module
   resolves it against the clock the handler reads. 0 disarms. Each runtime is its own
   module instance, so these statics are per runtime. */
#define DEADLINE_SAMPLE 16

static int64_t deadline_ns;
static int interrupted;
static int tick;

static int deadline_handler(JSRuntime *rt, void *opaque)
{
    (void)rt;
    (void)opaque;
    int64_t deadline = deadline_ns;
    if (deadline <= 0)
        return 0;
    /* QuickJS calls this every ~10k bytecodes; sampling the clock on one call in
       DEADLINE_SAMPLE coarsens the bound to ~100k bytecodes and keeps the WASI clock read
       off the hot path of a guest doing bulk work. The bound is a millisecond-scale guard
       against a guest that never yields, not a precise quantum. */
    if (++tick < DEADLINE_SAMPLE)
        return 0;
    tick = 0;
    if ((int64_t)js__hrtime_ns() <= deadline)
        return 0;
    interrupted = 1;
    return 1;
}

void QJS_SetDeadline(int64_t ns_from_now)
{
    deadline_ns = ns_from_now > 0 ? (int64_t)js__hrtime_ns() + ns_from_now : 0;
    tick = 0;
}

/* Whether the deadline has fired since this was last asked, and clears the flag. The
   embedder cannot learn it any other way: the throw lands in whatever job was running,
   and a job's exception is consumed by the job loop rather than returned to whoever
   drained the queue. */
int QJS_TakeInterrupted(void)
{
    int fired = interrupted;
    interrupted = 0;
    return fired;
}

/* ── unhandled rejections ────────────────────────────────────────────────────
   For a runtime that asks (QJS_New's track_rejections): a promise rejected with no handler
   joins the list and leaves it if a handler arrives later, and QJS_RunJobs reports what is
   still listed once the queue is empty — Node's rule for an unhandled rejection. */
typedef struct {
    JSValue promise;
    JSValue reason;
} Rejection;

static Rejection *rejections;
static size_t rejection_count;
static size_t rejection_cap;

static void track_rejection(JSContext *ctx, JSValueConst promise, JSValueConst reason,
                            bool is_handled, void *opaque)
{
    (void)opaque;
    size_t i;
    for (i = 0; i < rejection_count; i++)
        if (JS_VALUE_GET_PTR(rejections[i].promise) == JS_VALUE_GET_PTR(promise))
            break;
    if (is_handled) {
        if (i == rejection_count)
            return;
        JS_FreeValue(ctx, rejections[i].promise);
        JS_FreeValue(ctx, rejections[i].reason);
        memmove(&rejections[i], &rejections[i + 1],
                (rejection_count - i - 1) * sizeof(Rejection));
        rejection_count--;
        return;
    }
    if (i < rejection_count)
        return;
    if (rejection_count == rejection_cap) {
        size_t cap = rejection_cap ? rejection_cap * 2 : 8;
        Rejection *grown = realloc(rejections, cap * sizeof(Rejection));
        if (!grown)
            return;
        rejections = grown;
        rejection_cap = cap;
    }
    rejections[rejection_count].promise = JS_DupValue(ctx, promise);
    rejections[rejection_count].reason = JS_DupValue(ctx, reason);
    rejection_count++;
}

/* The oldest listed rejection's reason, removed from the list; the caller owns it. */
JSValue QJS_TakeRejection(JSContext *ctx)
{
    if (rejection_count == 0)
        return JS_UNDEFINED;
    Rejection r = rejections[0];
    memmove(&rejections[0], &rejections[1], (rejection_count - 1) * sizeof(Rejection));
    rejection_count--;
    JS_FreeValue(ctx, r.promise);
    return r.reason;
}

/* Drains the job queue. Answers -1 when a job failed (its exception pending), otherwise the
   number of unhandled rejections left once the queue is empty (QJS_TakeRejection). */
int QJS_RunJobs(JSContext *ctx)
{
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSContext *job_ctx;
    int err;
    while ((err = JS_ExecutePendingJob(rt, &job_ctx)) > 0) {
    }
    if (err < 0 || JS_HasException(ctx))
        return -1;
    return (int)rejection_count;
}

/* ── runtime ─────────────────────────────────────────────────────────────── */

/* One runtime and its one context. The stack limit is the engine default, which the
   linker's stack size leaves headroom under (qjswasm.cmake). */
JSContext *QJS_New(uint64_t memory_limit, int track_rejections)
{
    JSRuntime *rt = JS_NewRuntime();
    if (!rt)
        return NULL;
    JS_SetInterruptHandler(rt, deadline_handler, NULL);
    if (memory_limit > 0)
        JS_SetMemoryLimit(rt, memory_limit > SIZE_MAX ? SIZE_MAX : (size_t)memory_limit);
    if (track_rejections)
        JS_SetHostPromiseRejectionTracker(rt, track_rejection, NULL);
    JSContext *ctx = JS_NewContext(rt);
    if (!ctx)
        JS_FreeRuntime(rt);
    return ctx;
}

/* Re-reads the stack top from the depth every top-level call enters at. JS_NewRuntime
   read it from inside QJS_New, a few frames deeper. */
void QJS_UpdateStackTop(JSContext *ctx)
{
    JS_UpdateStackTop(JS_GetRuntime(ctx));
}

/* ── values ──────────────────────────────────────────────────────────────── */

void QJS_FreeValue(JSContext *ctx, JSValue v) { JS_FreeValue(ctx, v); }
JSValue QJS_DupValue(JSContext *ctx, JSValue v) { return JS_DupValue(ctx, v); }

JSValue QJS_Null(void) { return JS_NULL; }
JSValue QJS_Undefined(void) { return JS_UNDEFINED; }
JSValue QJS_NewBool(JSContext *ctx, int b) { return JS_NewBool(ctx, b != 0); }
JSValue QJS_NewInt32(JSContext *ctx, int32_t v) { return JS_NewInt32(ctx, v); }
JSValue QJS_NewInt64(JSContext *ctx, int64_t v) { return JS_NewInt64(ctx, v); }

/* The double arrives as its bits, so the ABI stays integer-only. */
JSValue QJS_NewFloat64(JSContext *ctx, uint64_t bits)
{
    double d;
    memcpy(&d, &bits, sizeof d);
    return JS_NewFloat64(ctx, d);
}

bool QJS_IsUndefined(JSValue v) { return JS_IsUndefined(v); }
bool QJS_IsNull(JSValue v) { return JS_IsNull(v); }
bool QJS_IsObject(JSValue v) { return JS_IsObject(v); }

/* 0 when the conversion throws, with the exception left pending. */
int32_t QJS_ToInt32(JSContext *ctx, JSValue v)
{
    int32_t r = 0;
    JS_ToInt32(ctx, &r, v);
    return r;
}

int64_t QJS_ToInt64(JSContext *ctx, JSValue v)
{
    int64_t r = 0;
    JS_ToInt64(ctx, &r, v);
    return r;
}

/* ── strings ─────────────────────────────────────────────────────────────── */

JSValue QJS_NewString(JSContext *ctx, const char *s, size_t len)
{
    return JS_NewStringLen(ctx, s, len);
}

/* The value as UTF-8, packed; 0 with the exception pending. The address is a string the
   caller releases with JS_FreeCString. */
uint64_t QJS_ToCString(JSContext *ctx, JSValue v)
{
    size_t len;
    const char *s = JS_ToCStringLen(ctx, &len, v);
    if (!s)
        return 0;
    return (uint64_t)(uintptr_t)s << 32 | (uint32_t)len;
}

/* ── bytes ───────────────────────────────────────────────────────────────── */

/* A zeroed ArrayBuffer of len bytes, for the caller to fill in place through
   QJS_GetBytes. */
JSValue QJS_NewArrayBuffer(JSContext *ctx, size_t len)
{
    return JS_NewArrayBufferCopy(ctx, NULL, len);
}

/* The bytes an ArrayBuffer or a TypedArray covers, packed; all ones with the exception
   pending. Read from the engine's own slots — no property lookup, so no JS runs, and
   nothing the caller wrote on the object is believed. The address is live storage, valid
   until JS next runs. */
uint64_t QJS_GetBytes(JSContext *ctx, JSValue v)
{
    size_t offset = 0, len, buffer_len;
    uint8_t *data;
    if (JS_IsException(v))
        return UINT64_MAX;
    if (JS_IsArrayBuffer(v)) {
        data = JS_GetArrayBuffer(ctx, &len, v);
    } else {
        JSValue buffer = JS_GetTypedArrayBuffer(ctx, v, &offset, &len, NULL);
        if (JS_IsException(buffer))
            return UINT64_MAX;
        data = JS_GetArrayBuffer(ctx, &buffer_len, buffer);
        JS_FreeValue(ctx, buffer);
    }
    if (!data)
        return UINT64_MAX;
    return (uint64_t)(uintptr_t)(data + offset) << 32 | (uint32_t)len;
}

/* ── functions and evaluation ────────────────────────────────────────────── */

static JSValue call_go(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv,
                       int magic, JSValueConst *data)
{
    (void)magic;
    return qjs_call_go(ctx, this_val, argc, argv, (uint32_t)JS_VALUE_GET_INT(data[0]));
}

/* A JS function that calls the Go function registered under id. */
JSValue QJS_NewFunction(JSContext *ctx, uint32_t id)
{
    JSValue data = JS_NewInt32(ctx, (int32_t)id);
    return JS_NewCFunctionData(ctx, call_go, 0, 0, 1, &data);
}

JSValue QJS_Call(JSContext *ctx, JSValue fn, JSValue this_val, int argc, JSValueConst *argv)
{
    return JS_Call(ctx, fn, this_val, argc, argv);
}

/* Evaluates strict global code and answers its completion value as it stands — a promise
   stays a promise. code[len] must be NUL, as JS_Eval requires. */
JSValue QJS_Eval(JSContext *ctx, const char *code, size_t len, const char *filename)
{
    return JS_Eval(ctx, code, len, filename, JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT);
}

/* Throws a plain Error carrying msg, the shape a Go callback's error takes in JS. */
JSValue QJS_ThrowError(JSContext *ctx, const char *msg, size_t len)
{
    JSValue err = JS_NewError(ctx);
    if (JS_IsException(err))
        return err;
    JS_SetPropertyStr(ctx, err, "message", JS_NewStringLen(ctx, msg, len));
    return JS_Throw(ctx, err);
}

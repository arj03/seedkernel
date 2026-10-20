/* A confined guest realm (§12.3) behind a byte-level ABI, for an embedder that drives the
   engine from JavaScript through a generic wasm instance table (host/engine-realm.ts).

   shim.c's QJS_* ABI hands out JSValues as i64 handles, which a JS embedder could only
   carry as BigInts, and costs a call per value built or read. A realm needs far less: its
   embedder moves bytes in and out and never touches a guest value. So every export here
   takes and returns i32 and f64 (ids and durations are f64, a JS number on both sides),
   and bytes move through one exchange buffer in linear memory.

   The mechanics that run on every call live here rather than in the embedder, where they
   would be interpreted JS on the native target: each entry arms the execution deadline,
   runs the guest, drains the job queue and disarms, in one crossing; and the host-call
   ledger (count and byte caps, admission before the payload leaves the guest) is kept
   here. An entry answers -1 when the deadline fired (the realm survives it), a value at
   most -2 for a failure whose text is the first (-2 - r) bytes of the exchange buffer, or
   a non-negative result.

   The exchange buffer moves only when it grows (R_Buf), and every import that hands the
   embedder bytes passes its address, so an embedder can keep the address between calls.
   A failure text that would not fit is cut short.

   One instance is one realm: the runtime, its entry points, the ledger and the exchange
   buffer are statics. The guest preamble (host/guest-seam.ts) calls the three functions
   installed here as __host_call, __callDone and __callFail, which reach the embedder
   through the three `realm` imports. */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <quickjs.h>

/* From shim.c: the runtime constructor, which arms the deadline interrupt handler. */
JSContext *QJS_New(uint64_t memory_limit, int track_rejections);
void QJS_SetDeadline(int64_t ns_from_now);
int64_t QJS_DeadlineLeft(void);
int QJS_TakeInterrupted(void);

/* A guest's host.call. The exchange buffer at `buf` holds the name (|name_len| bytes; a
   negative length marks one that is not ASCII) and then the payload. remaining_ms is what
   is left of the running segment, -1 for an unbounded one. The answer is packed as
   (len << 2) | kind: kind 0 parked (the embedder settles it later through R_Settle), 1
   answered, 2 rejected, 3 refused (thrown at the call site). For 1 to 3, the bytes are the
   first len bytes of the exchange buffer. */
__attribute__((import_module("realm"), import_name("hostCall")))
extern int32_t realm_host_call(double call_id, double remaining_ms, uint8_t *buf,
                               int32_t name_len, int32_t payload_len);
/* An invocation's answer bytes, or the message it failed with. */
__attribute__((import_module("realm"), import_name("callDone")))
extern void realm_call_done(double id, const uint8_t *bytes, int32_t len);
__attribute__((import_module("realm"), import_name("callFail")))
extern void realm_call_fail(double id, const char *msg, int32_t len);

enum { ANSWER_PARKED, ANSWER_BYTES, ANSWER_REJECT, ANSWER_THROW };

#define INTERRUPTED (-1)
#define FIRST_BUF 4096

static JSContext *ctx;
static JSValue start_fn, resolve_fn, reject_fn;

static uint8_t *xbuf;
static size_t xcap;

/* The exchange buffer, grown to hold len bytes plus a NUL; its address. 0 when memory runs
   out, which leaves the old buffer in place. */
uint8_t *R_Buf(int32_t len)
{
    size_t need = (size_t)(len < 0 ? 0 : len) + 1;
    if (need > xcap) {
        size_t cap = xcap ? xcap : FIRST_BUF;
        while (cap < need)
            cap *= 2;
        uint8_t *grown = realloc(xbuf, cap);
        if (!grown)
            return 0;
        xbuf = grown;
        xcap = cap;
    }
    return xbuf;
}

/* Appends what fits of s at xbuf + at, answering the new length. */
static size_t append(size_t at, const char *s, size_t len)
{
    if (at + len > xcap)
        len = xcap - at;
    memcpy(xbuf + at, s, len);
    return at + len;
}

/* Takes the pending exception into the exchange buffer as its text, with its stack when it
   has one (the shape qjs/value.go's asError gives native errors). */
static int32_t fail(void)
{
    JSValue exc = JS_GetException(ctx);
    size_t len = 0, slen = 0, n = 0;
    const char *msg = JS_ToCStringLen(ctx, &len, exc);
    const char *stack = NULL;
    if (JS_IsObject(exc)) {
        JSValue s = JS_GetPropertyStr(ctx, exc, "stack");
        if (!JS_IsUndefined(s) && !JS_IsException(s))
            stack = JS_ToCStringLen(ctx, &slen, s);
        JS_FreeValue(ctx, s);
    }
    if (JS_HasException(ctx))
        JS_FreeValue(ctx, JS_GetException(ctx));
    if (!msg) {
        static const char unreadable[] = "guest: exception could not be read";
        n = append(0, unreadable, sizeof unreadable - 1);
    } else {
        n = append(0, msg, len);
        if (stack) {
            n = append(n, "\n", 1);
            n = append(n, stack, slen);
        }
        JS_FreeCString(ctx, msg);
    }
    if (stack)
        JS_FreeCString(ctx, stack);
    JS_FreeValue(ctx, exc);
    return -2 - (int32_t)n;
}

/* Drains the job queue: 0, or the failure of the job that threw. */
static int32_t run_jobs(void)
{
    JSRuntime *rt = JS_GetRuntime(ctx);
    JSContext *job_ctx;
    int err;
    while ((err = JS_ExecutePendingJob(rt, &job_ctx)) > 0) {
    }
    return err < 0 ? fail() : 0;
}

/* Ends an entry: disarms the deadline, and lets a fired deadline outrank the result. */
static int32_t leave(int32_t r)
{
    QJS_SetDeadline(0);
    if (QJS_TakeInterrupted()) {
        if (JS_HasException(ctx))
            JS_FreeValue(ctx, JS_GetException(ctx));
        return INTERRUPTED;
    }
    return r;
}

/* ── the host-call ledger ───────────────────────────────────────────────────
   Every call between its admission and its answer, by guest-minted id, with the bytes it
   holds: its payload, and its answer while that is copied in. Bounded by count and by
   aggregate bytes (host/wasm-limits.ts, passed to R_Init). */
typedef struct {
    double id;
    size_t bytes;
} Call;

static Call *calls;
static int call_count, max_calls;
static size_t call_bytes, max_bytes;
static char why[96];

static int find_call(double id)
{
    for (int i = 0; i < call_count; i++)
        if (calls[i].id == id)
            return i;
    return -1;
}

/* Charges bytes to the aggregate allowance, or answers why not and charges nothing. */
static const char *charge(size_t bytes)
{
    if (bytes > max_bytes - call_bytes) {
        snprintf(why, sizeof why, "guest: too many outstanding host call payload bytes (cap %zu)", max_bytes);
        return why;
    }
    call_bytes += bytes;
    return NULL;
}

static const char *admit(double id, size_t bytes)
{
    if (!(id >= 0 && id <= 9007199254740991.0 && id == (double)(int64_t)id))
        return "guest: invalid host call id";
    if (find_call(id) >= 0) {
        snprintf(why, sizeof why, "guest: duplicate live host call id %lld", (long long)id);
        return why;
    }
    if (call_count >= max_calls) {
        snprintf(why, sizeof why, "guest: too many outstanding host calls (cap %d)", max_calls);
        return why;
    }
    const char *refused = charge(bytes);
    if (refused)
        return refused;
    calls[call_count].id = id;
    calls[call_count].bytes = bytes;
    call_count++;
    return NULL;
}

/* Charges an admitted call's answer, or answers why not. */
static const char *reserve(int i, size_t bytes)
{
    const char *refused = charge(bytes);
    if (!refused)
        calls[i].bytes += bytes;
    return refused;
}

static void release(int i)
{
    call_bytes -= calls[i].bytes;
    calls[i] = calls[--call_count];
}

static JSValue throw_message(JSContext *c, const char *msg, size_t len)
{
    JSValue err = JS_NewError(c);
    if (JS_IsException(err))
        return err;
    JS_SetPropertyStr(c, err, "message", JS_NewStringLen(c, msg, len));
    return JS_Throw(c, err);
}

static JSValue host_call(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv)
{
    (void)this_val;
    (void)argc;
    double id;
    size_t name_len, payload_len;
    if (JS_ToFloat64(c, &id, argv[1]) < 0)
        return JS_EXCEPTION;
    uint8_t *payload = JS_GetArrayBuffer(c, &payload_len, argv[2]);
    if (!payload && JS_HasException(c))
        return JS_EXCEPTION;
    /* Admitted before the payload leaves the guest heap. */
    const char *refused = admit(id, payload_len);
    if (refused)
        return throw_message(c, refused, strlen(refused));
    int i = call_count - 1;
    const char *name = JS_ToCStringLen(c, &name_len, argv[0]);
    if (!name || !R_Buf((int32_t)(name_len + payload_len))) {
        release(i);
        if (name)
            JS_FreeCString(c, name);
        return name ? JS_ThrowOutOfMemory(c) : JS_EXCEPTION;
    }
    int ascii = 1;
    for (size_t k = 0; k < name_len; k++)
        ascii &= (unsigned char)name[k] < 0x80;
    memcpy(xbuf, name, name_len);
    memcpy(xbuf + name_len, payload, payload_len);
    JS_FreeCString(c, name);
    int64_t left = QJS_DeadlineLeft();
    int32_t r = realm_host_call(id, left < 0 ? -1.0 : (double)left / 1e6, xbuf,
                                ascii ? (int32_t)name_len : -(int32_t)name_len, (int32_t)payload_len);
    size_t len = (size_t)((uint32_t)r >> 2);
    int kind = r & 3;
    if (kind == ANSWER_PARKED)
        return JS_NULL;
    /* The import cannot have settled this call, so it is still in the ledger. */
    i = find_call(id);
    JSValue v;
    if (kind == ANSWER_BYTES) {
        /* Charged while it is copied in; a refused copy rejects with the reason. */
        refused = reserve(i, len);
        v = refused ? JS_NewString(c, refused) : JS_NewArrayBufferCopy(c, xbuf, len);
    } else if (kind == ANSWER_REJECT) {
        v = JS_NewStringLen(c, (const char *)xbuf, len);
    } else {
        v = throw_message(c, (const char *)xbuf, len);
    }
    release(i);
    return v;
}

static JSValue call_done(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv)
{
    (void)this_val;
    (void)argc;
    double id;
    size_t len;
    if (JS_ToFloat64(c, &id, argv[0]) < 0)
        return JS_EXCEPTION;
    uint8_t *bytes = JS_GetArrayBuffer(c, &len, argv[1]);
    if (!bytes && JS_HasException(c)) {
        JS_FreeValue(c, JS_GetException(c));
        static const char msg[] = "guest: entrypoint result is not bytes";
        realm_call_fail(id, msg, (int32_t)(sizeof msg - 1));
        return JS_UNDEFINED;
    }
    realm_call_done(id, bytes, (int32_t)len);
    return JS_UNDEFINED;
}

static JSValue call_fail(JSContext *c, JSValueConst this_val, int argc, JSValueConst *argv)
{
    (void)this_val;
    (void)argc;
    double id;
    size_t len;
    if (JS_ToFloat64(c, &id, argv[0]) < 0)
        return JS_EXCEPTION;
    const char *msg = JS_ToCStringLen(c, &len, argv[1]);
    if (!msg)
        return JS_EXCEPTION;
    realm_call_fail(id, msg, (int32_t)len);
    JS_FreeCString(c, msg);
    return JS_UNDEFINED;
}

static void set_global_fn(const char *name, JSCFunction *fn, int length)
{
    JSValue global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, name, JS_NewCFunction(ctx, fn, name, length));
    JS_FreeValue(ctx, global);
}

/* Builds the realm: intrinsics, a heap capped at memory_limit bytes, the host-call caps,
   the three seam functions, and the exchange buffer. 0, or -2 when the engine could not
   start. */
int32_t R_Init(double memory_limit, int32_t outstanding_calls, double outstanding_bytes)
{
    if (outstanding_calls <= 0 || outstanding_bytes <= 0 || !R_Buf(FIRST_BUF - 1))
        return -2;
    calls = calloc((size_t)outstanding_calls, sizeof *calls);
    if (!calls)
        return -2;
    max_calls = outstanding_calls;
    max_bytes = (size_t)outstanding_bytes;
    ctx = QJS_New((uint64_t)memory_limit, 0);
    if (!ctx)
        return -2;
    /* Every later entry starts at this depth (shim.c, QJS_UpdateStackTop). */
    JS_UpdateStackTop(JS_GetRuntime(ctx));
    start_fn = resolve_fn = reject_fn = JS_UNDEFINED;
    set_global_fn("__host_call", host_call, 3);
    set_global_fn("__callDone", call_done, 2);
    set_global_fn("__callFail", call_fail, 2);
    return 0;
}

/* Evaluates the len bytes of the exchange buffer as strict global code under a deadline of
   deadline_ns (0 for none). `preamble` 1 also takes the preamble's entry points, before
   any guest code can replace them with getters. 0 on success. */
int32_t R_Eval(int32_t len, int32_t preamble, double deadline_ns)
{
    xbuf[len] = 0;
    QJS_SetDeadline((int64_t)deadline_ns);
    JSValue v = JS_Eval(ctx, (const char *)xbuf, (size_t)len,
                        preamble ? "guest-preamble.js" : "guest.js",
                        JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT);
    if (JS_IsException(v))
        return leave(fail());
    JS_FreeValue(ctx, v);
    if (preamble) {
        JSValue global = JS_GetGlobalObject(ctx);
        start_fn = JS_GetPropertyStr(ctx, global, "__start");
        resolve_fn = JS_GetPropertyStr(ctx, global, "__resolveHostCall");
        reject_fn = JS_GetPropertyStr(ctx, global, "__rejectHostCall");
        JS_FreeValue(ctx, global);
    }
    return leave(0);
}

/* Runs one invocation, __start(id, the len bytes of the exchange buffer), and drains the
   jobs it queued. Answers 1 when the guest deferred its answer, 0 when not. */
int32_t R_Invoke(double id, int32_t len, double deadline_ns)
{
    JSValue args[2] = { JS_NewFloat64(ctx, id), JS_NewArrayBufferCopy(ctx, xbuf, (size_t)len) };
    QJS_SetDeadline((int64_t)deadline_ns);
    JSValue r = JS_Call(ctx, start_fn, JS_UNDEFINED, 2, args);
    JS_FreeValue(ctx, args[1]);
    if (JS_IsException(r))
        return leave(fail());
    int32_t deferred = 0;
    JS_ToInt32(ctx, &deferred, r);
    JS_FreeValue(ctx, r);
    int32_t jobs = run_jobs();
    return leave(jobs < 0 ? jobs : deferred == 1);
}

/* Settles a parked host.call, resolving it with the len bytes of the exchange buffer when
   ok is 1 or rejecting it with them as the message, and drains the continuation. An answer
   the ledger cannot hold rejects with the reason instead. 0 on success, and for a call no
   longer parked, which there is nothing to settle. */
int32_t R_Settle(double call_id, int32_t ok, int32_t len, double deadline_ns)
{
    int i = find_call(call_id);
    if (i < 0)
        return 0;
    JSValue arg;
    const char *refused = ok ? reserve(i, (size_t)len) : NULL;
    if (refused) {
        ok = 0;
        arg = JS_NewString(ctx, refused);
    } else {
        arg = ok ? JS_NewArrayBufferCopy(ctx, xbuf, (size_t)len)
                 : JS_NewStringLen(ctx, (const char *)xbuf, (size_t)len);
    }
    release(i);
    JSValue args[2] = { JS_NewFloat64(ctx, call_id), arg };
    QJS_SetDeadline((int64_t)deadline_ns);
    JSValue r = JS_Call(ctx, ok ? resolve_fn : reject_fn, JS_UNDEFINED, 2, args);
    JS_FreeValue(ctx, arg);
    if (JS_IsException(r))
        return leave(fail());
    JS_FreeValue(ctx, r);
    return leave(run_jobs());
}

#include "qjs.h"

JSContext *New_QJSContext(JSRuntime *rt)
{
  JSContext *ctx;
  ctx = JS_NewContext(rt);
  js_init_module_std(ctx, "qjs:std");
  js_init_module_os(ctx, "qjs:os");
  js_init_module_bjson(ctx, "qjs:bjson");
  js_set_global_objs(ctx);

  return ctx;
}

QJSRuntime *New_QJS(
    size_t memory_limit,
    size_t max_stack_size,
    size_t max_execution_time,
    size_t gc_threshold)
{
  JSRuntime *runtime;
  JSContext *ctx;

#ifdef QJS_DEBUG_RUNTIME_ADDRESS
  randomize_address_space();
#endif

  runtime = JS_NewRuntime();

  if (!runtime)
    return NULL;

  /* The execution bound. max_execution_time stays in the signature for ABI
     compatibility, but the deadline is armed through QJS_SetDeadline instead —
     one handler for the runtime's whole life, disarmed until an embedder asks. */
  (void)max_execution_time;
  JS_SetInterruptHandler(runtime, QJS_DeadlineHandler, NULL);

  if (memory_limit > 0)
    JS_SetMemoryLimit(runtime, memory_limit);

  if (gc_threshold > 0)
    JS_SetGCThreshold(runtime, gc_threshold);

  if (max_stack_size > 0)
    JS_SetMaxStackSize(runtime, max_stack_size);

  /* setup the the worker context */
  js_std_set_worker_new_context_func(New_QJSContext);
  /* initialize the standard objects */
  js_std_init_handlers(runtime);
  /* loader for ES6 modules */
  JS_SetModuleLoaderFunc(runtime, NULL, QJS_ModuleLoader, NULL);
  /* exit on unhandled promise rejections */
  // JS_SetHostPromiseRejectionTracker(runtime, js_std_promise_rejection_tracker, NULL);

  ctx = New_QJSContext(runtime);
  if (!ctx)
  {
    JS_FreeRuntime(runtime);
    return NULL;
  }

  // Initialize QJS_PROXY_VALUE class
  if (init_qjs_proxy_value_class(ctx) < 0)
  {
    JS_FreeContext(ctx);
    JS_FreeRuntime(runtime);
    return NULL;
  }

  QJSRuntime *qjs = (QJSRuntime *)malloc(sizeof(QJSRuntime));
  if (!qjs)
  {
    JS_FreeContext(ctx);
    JS_FreeRuntime(runtime);
    return NULL;
  }

  qjs->runtime = runtime;
  qjs->context = ctx;

  return qjs;
}

void QJS_FreeValue(JSContext *ctx, JSValue val)
{
  JS_FreeValue(ctx, val);
}

void QJS_Free(QJSRuntime *qjs)
{
  JS_FreeContext(qjs->context);
  JS_FreeRuntime(qjs->runtime);
  free(qjs);
}

JSValue QJS_CloneValue(JSContext *ctx, JSValue val)
{
  return JS_DupValue(ctx, val);
}

JSContext *QJS_GetContext(QJSRuntime *qjs)
{
  return qjs->context;
}

void QJS_UpdateStackTop(QJSRuntime *qjs)
{
  JS_UpdateStackTop(qjs->runtime);
}

QJSRuntime *qjs = NULL;

QJSRuntime *QJS_GetRuntime()
{
  return qjs;
}

void initialize()
{
  if (qjs != NULL)
    return;
  size_t memory_limit = 0;
  size_t gc_threshold = 0;
  size_t max_stack_size = 0;
  qjs = New_QJS(memory_limit, max_stack_size, 0, gc_threshold);
}

/* ── execution deadline ──────────────────────────────────────────────────────
   QuickJS's own interrupt lever, wired to a monotonic deadline. New_QJS's
   max_execution_time argument never did anything (its handler is commented out in
   helpers.c), so the only bound an embedder had was killing the wasm call from
   outside — which costs a termination check compiled into every loop, and takes
   the whole module down with it. This is the cheap half of that trade: one clock
   read per 10k bytecodes, and the interrupt surfaces as an ordinary catchable JS
   exception, so the runtime survives its own budget kill.

   The deadline is absolute (js__hrtime_ns), set through QJS_SetDeadline so the
   embedder never has to share a clock origin with the module: it passes a
   duration, the module resolves it against the clock the handler will read.
   0 disarms. */
#define QJS_DEADLINE_SAMPLE 16

static int64_t qjs_deadline_ns = 0;
static int qjs_interrupted = 0;
static int qjs_tick = 0;

/* Whether the deadline has fired since this was last asked, and clears the flag.

   The embedder needs this because an interrupt is NOT visible in the return value of
   the call it stopped: the throw lands in whatever job was running, and a job's
   exception is consumed by the job loop rather than propagated to the caller of
   JS_Eval. Without a flag, a host driving the job queue cannot tell a guest that ran
   out of budget from one that simply finished. */
int QJS_TakeInterrupted(void)
{
  int fired = qjs_interrupted;
  qjs_interrupted = 0;
  return fired;
}

void QJS_SetDeadline(int64_t ns_from_now)
{
  qjs_deadline_ns = ns_from_now > 0 ? (int64_t)js__hrtime_ns() + ns_from_now : 0;
  qjs_tick = 0;
}

int QJS_DeadlineHandler(JSRuntime *rt, void *opaque)
{
  (void)rt;
  (void)opaque;
  int64_t deadline = qjs_deadline_ns;
  if (deadline <= 0)
    return 0;
  /* QuickJS already calls this only every ~10k bytecodes; sampling the clock on one
     call in QJS_DEADLINE_SAMPLE coarsens the bound to ~100k bytecodes and keeps the
     WASI clock read off the hot path of a guest doing bulk work. The bound is a
     millisecond-scale guard against a guest that never yields, not a precise quantum,
     so trading resolution no embedder relies on for the throughput of every guest that
     behaves is the right side of that trade. */
  if (++qjs_tick < QJS_DEADLINE_SAMPLE)
    return 0;
  qjs_tick = 0;
  if ((int64_t)js__hrtime_ns() <= deadline)
    return 0;
  qjs_interrupted = 1;
  return 1;
}

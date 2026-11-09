// quic.wasm: the connection of a UDP path (§12.7), ngtcp2 behind the pure-module ABI (§4).
// The transport's udp.js finds the path and owns the socket; this module is the QUIC
// connection over it, one per path, and touches no socket: datagrams come in with each call
// and the datagrams to send go out in its answer. A listening socket carries many paths,
// which udp.js tells apart by the connection IDs each one names (`OP_TURN`), and a
// stranger's address is validated with a stateless Retry before a path opens for it
// (`OP_SCREEN`).
//
// The link's own handshake (ake.js) is the connection's, in TLS's place: its messages cross
// in CRYPTO frames, which this module hands up and takes down, and it hands down the keys
// it derives. The Initial packets carry the link's first two messages under fixed keys,
// since those messages conceal themselves; the Handshake packets carry its third and each
// end's transport parameters under keys both ends derive once the second has crossed; and
// the 1-RTT packets go under the link's session keys. So every packet past the handshake is
// sealed under keys only the two authenticated ends hold, once: the link's records go in the
// clear above the connection.
//
// Every packet is ChaCha20-Poly1305 with ChaCha20 header protection, as RFC 9001 §5.4.4 has
// for that suite; the derivations are BLAKE2b, keyed (Monocypher).
#include <ngtcp2/ngtcp2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.h"

// ── the module ABI (§4) ──────────────────────────────────────────────────────

/** A turn takes a whole `datagrams` event, up to the host's 2 MiB read cap; its size is the
 *  `scratchSize` export scratch.wat adds. */
#define SCRATCH_BYTES (2560 * 1024)
uint8_t scratch[SCRATCH_BYTES];

/** ngtcp2's unreachable and its asserts, which it keeps in a release build, would print
 *  through WASI before they abort: here they trap, which the host takes as a failed call,
 *  and the module reaches no WASI at all. */
void ngtcp2_unreachable_fail(const char *file, int line, const char *func) { __builtin_trap(); }
void __assert_fail(const char *expr, const char *file, int line, const char *func) { __builtin_trap(); }
/** The only stdio ngtcp2 names is in debug printers nothing calls. Answering it here keeps
 *  wasi-libc's stdio, whose exit hook would import WASI's writes, out of the link. */
FILE *const stderr = NULL;
int fprintf(FILE *restrict f, const char *restrict fmt, ...) { return 0; }
int fputc(int c, FILE *f) { return c; }

enum { OP_OPEN = 1, OP_TURN = 2, OP_DROP = 3, OP_SCREEN = 4 };
/** A turn's flags. */
enum { F_FIN = 1, F_CLOSE = 2, F_HS_KEYS = 4, F_KEYS = 8 };
/** A turn's events: everything written is acked, the connection is over, and what came is
 *  not all read yet. */
enum { E_FINISHED = 1, E_CLOSED = 2, E_MORE = 4 };

/** What one answer sends at most: what one `link/udpSend` takes, less a datagram. */
#define SEND_MAX (256 * 1024 - 1600)
/** The most one answer reads: quic.js asks for 256 KiB at most. */
#define READ_MAX (256 * 1024)
/** What one level's handshake messages may weigh while they arrive: the link's first, with
 *  its post-quantum key, is 1233 bytes. */
#define HS_MAX 4096
/** How many times a close is sent: the path goes at once, with no closing period to answer
 *  the peer's packets with it again, and nothing acks it. */
#define CLOSE_COPIES 3
/** The answer is built here, since the input it answers is still being read from scratch. */
static uint8_t answer[64 + READ_MAX + 2 * HS_MAX + SEND_MAX + (1 + CLOSE_COPIES) * 1600];

/** The input, read in order; any read past its end fails the call. */
typedef struct {
  const uint8_t *b;
  size_t n, at;
  int bad;
} reader;

static const uint8_t *take(reader *r, size_t n) {
  if (r->bad || n > r->n - r->at) {
    r->bad = 1;
    return NULL;
  }
  r->at += n;
  return r->b + r->at - n;
}

static uint32_t u8(reader *r) { const uint8_t *p = take(r, 1); return p ? p[0] : 0; }
static uint32_t u16(reader *r) { const uint8_t *p = take(r, 2); return p ? (uint32_t)p[0] << 8 | p[1] : 0; }
static uint32_t u32(reader *r) {
  const uint8_t *p = take(r, 4);
  return p ? (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3] : 0;
}
static double f64(reader *r) {
  const uint8_t *p = take(r, 8);
  uint64_t v = 0;
  for (int i = 0; p && i < 8; i++) v = v << 8 | p[i];
  double d;
  memcpy(&d, &v, 8);
  return d;
}

static size_t out_at;
static void put(const void *b, size_t n) {
  memcpy(answer + out_at, b, n);
  out_at += n;
}
static void put_u16(uint32_t v) { uint8_t b[2] = {v >> 8, v}; put(b, 2); }
static void put_u32(uint32_t v) { uint8_t b[4] = {v >> 24, v >> 16, v >> 8, v}; put(b, 4); }
static void put_u32_at(size_t at, uint32_t v) {
  answer[at] = v >> 24, answer[at + 1] = v >> 16, answer[at + 2] = v >> 8, answer[at + 3] = v;
}
static void put_f64_at(size_t at, double d) {
  uint64_t v;
  memcpy(&v, &d, 8);
  for (int i = 7; i >= 0; i--, v >>= 8) answer[at + i] = (uint8_t)v;
}

/** An address as the batches carry it and OPEN the peer's: `[n u8][ip n][port u16]`, n 4
 *  for IPv4 and 16 for IPv6. */
static int read_addr(reader *r, ngtcp2_sockaddr_union *a) {
  memset(a, 0, sizeof *a);
  uint32_t n = u8(r);
  if (n != 4 && n != 16) r->bad = 1;
  const uint8_t *ip = take(r, n);
  uint16_t port = (uint16_t)u16(r);
  if (r->bad) return 0;
  if (n == 4) {
    a->in.sin_family = NGTCP2_AF_INET;
    memcpy(&a->in.sin_addr, ip, 4);
    a->in.sin_port = port;
  } else {
    a->in6.sin6_family = NGTCP2_AF_INET6;
    memcpy(&a->in6.sin6_addr, ip, 16);
    a->in6.sin6_port = port;
  }
  return 1;
}

static ngtcp2_socklen addr_len(const ngtcp2_sockaddr_union *a) {
  return a->sa.sa_family == NGTCP2_AF_INET ? sizeof a->in : sizeof a->in6;
}

/** One datagram as `link/udpSend` takes it, `[socket u32][n u8][ip n][port u16][len u16]
 *  [bytes]`, an IPv4-mapped address as IPv4. */
static void put_send(uint32_t socket, const ngtcp2_sockaddr_union *to, const uint8_t *bytes, size_t len) {
  static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  const uint8_t *ip = (const uint8_t *)&to->in.sin_addr;
  uint8_t n = 4;
  uint16_t port = to->in.sin_port;
  if (to->sa.sa_family == NGTCP2_AF_INET6) {
    ip = to->in6.sin6_addr.s6_addr;
    port = to->in6.sin6_port;
    if (memcmp(ip, mapped, 12)) n = 16;
    else ip += 12;
  }
  put_u32(socket);
  put(&n, 1);
  put(ip, n);
  put_u16(port);
  put_u16((uint32_t)len);
  put(bytes, len);
}

// ── time ─────────────────────────────────────────────────────────────────────

/** Where the realm's clock, which may start near zero, sits on ngtcp2's: far enough on that
 *  its reckoning back from now never runs below zero. */
#define EPOCH_NS (1ULL << 50)

static ngtcp2_tstamp ts_of(double ms) { return EPOCH_NS + (uint64_t)((ms > 0 ? ms : 0) * 1e6); }

// ── keys ─────────────────────────────────────────────────────────────────────

/** BLAKE2b-256 keyed with `key`, over `label`. */
static void kdf(uint8_t out[32], const uint8_t key[32], const char *label) {
  crypto_blake2b_keyed(out, 32, key, 32, (const uint8_t *)label, strlen(label));
}

/** A secret's packet key, as an AEAD or header-protection context holds it. */
static void *key_of(const uint8_t secret[32], const char *label) {
  uint8_t *k = malloc(32);
  if (k) kdf(k, secret, label);
  return k;
}

static void iv_of(uint8_t iv[12], const uint8_t secret[32]) {
  uint8_t t[32];
  kdf(t, secret, "seedkernel-quic-iv-v1");
  memcpy(iv, t, 12);
}

/** How many packets a 1-RTT key seals before ngtcp2 updates it. */
#define GENERATION_PACKETS (1ULL << 24)

static ngtcp2_crypto_ctx crypto_ctx(void) {
  ngtcp2_crypto_ctx c = {0};
  c.aead.max_overhead = 16;
  c.max_encryption = GENERATION_PACKETS;
  c.max_decryption_failure = 1ULL << 36;
  return c;
}

/** One level's keys, from its two secrets, this end's first. */
typedef struct {
  uint8_t iv[2][12];
  ngtcp2_crypto_aead_ctx aead[2];
  ngtcp2_crypto_cipher_ctx hp[2];
} level_keys;

static int level_keys_of(const uint8_t *secrets, level_keys *l) {
  for (int d = 0; d < 2; d++) {
    const uint8_t *s = secrets + 32 * d;
    iv_of(l->iv[d], s);
    l->aead[d].native_handle = key_of(s, "seedkernel-quic-key-v1");
    l->hp[d].native_handle = key_of(s, "seedkernel-quic-hp-v1");
    if (!l->aead[d].native_handle || !l->hp[d].native_handle) return -1;
  }
  return 0;
}

// ── paths ────────────────────────────────────────────────────────────────────

/** The datagrams a path holds while its handshake runs (`held`): the newest this many. */
#define HELD_MAX 8

/** The window each stream has, and the connection with it; also the most of what was
 *  written that the connection holds until it is acked. */
#define WINDOW (4u << 20)
/** What was written is held in chunks of this size, allocated as it comes and freed as it
 *  is acked, so a path holds what it has in flight and no more. */
#define CHUNK (64u * 1024)
#define CHUNKS (WINDOW / CHUNK)
/** What was written and not yet sent the connection takes at most: past it, what the link
 *  writes waits in the realm, so a sender faster than its path costs the module nothing. */
#define QUEUE_MAX (256u * 1024)

typedef struct path path;
struct path {
  uint32_t id, socket;
  int server;
  ngtcp2_conn *conn;
  /** The server's peer, the one address its connection is taken from. */
  ngtcp2_sockaddr_union peer;
  ngtcp2_sockaddr_union local;
  /** A listener's: the key its Retry tokens are checked under (`token_ok`), and whether the
   *  connection IDs it answers to changed since an answer last named them. */
  int listener, cids_dirty;
  uint8_t listen_key[32];
  uint8_t seed[32];
  uint32_t rng_ctr;
  /** Each level's handshake data as it comes, ngtcp2 handing it over in pieces; what of it
   *  is the link's, for the answer; the link's messages sent so far; and whether the peer's
   *  transport parameters are in and the link has its session keys (`F_KEYS`). */
  uint8_t hs[2][HS_MAX];
  size_t hs_len[2];
  uint8_t hs_up[2 * HS_MAX];
  size_t hs_up_len;
  int hs_sent, have_params, have_keys, completed;
  /** The server's: the client's Initial parameters, taken and held to check (above). */
  int initial_params;
  uint8_t params[32];
  /** The link's session keys, held until the handshake completes (`complete`). */
  uint8_t keys[64];
  /** The datagrams that came while the handshake runs. One that came before the keys to
   *  open it ngtcp2 could only buffer, and replays only on a later read, while the link's
   *  keys come on a turn of their own: each is read again once keys go in (`replay`), and
   *  ngtcp2 drops what it has already read. */
  struct {
    ngtcp2_sockaddr_union from;
    size_t len;
    uint8_t b[1500];
  } held[HELD_MAX];
  int nheld;
  /** A stream each way, each end opening its own so neither waits on the other to speak:
   *  this end's, and the peer's, of which what came and is not yet read is
   *  `rbuf[rhead, rhead + rlen)`. */
  int64_t stream, rstream;
  uint8_t *rbuf;
  size_t rhead, rlen, rcap;
  /** What was written, from the first byte not yet acked, as stream offsets: offset `o` is
   *  byte `o % CHUNK` of chunk `(o / CHUNK) % CHUNKS`, which ngtcp2 reads until acked. */
  uint8_t *chunk[CHUNKS];
  uint64_t acked, sent, end;
  int fin_wanted, fin_sent;
  uint8_t events;
  int finished_told, closed;
  path *next;
};

static path *paths;

/** The Initial keys, fixed: the link's first two messages conceal themselves. */
static int install_initial(path *p) {
  static const uint8_t fixed[32];
  uint8_t s[64];
  level_keys l;
  ngtcp2_crypto_ctx c = crypto_ctx();
  kdf(s + (p->server ? 32 : 0), fixed, "seedkernel-quic-initial-client-v1");
  kdf(s + (p->server ? 0 : 32), fixed, "seedkernel-quic-initial-server-v1");
  if (level_keys_of(s, &l)) return -1;
  ngtcp2_conn_set_initial_crypto_ctx(p->conn, &c);
  return ngtcp2_conn_install_initial_key(p->conn, &l.aead[1], l.iv[1], &l.hp[1], &l.aead[0], l.iv[0], &l.hp[0], 12);
}

/** This end's transport parameters, at level `lv`. */
static int submit_params(path *p, ngtcp2_encryption_level lv) {
  uint8_t b[512];
  ngtcp2_ssize n = ngtcp2_conn_encode_local_transport_params(p->conn, b + 3, sizeof b - 3);
  if (n < 0) return -1;
  b[0] = 2, b[1] = (uint8_t)(n >> 8), b[2] = (uint8_t)n;
  return ngtcp2_conn_submit_crypto_data(p->conn, lv, b, (size_t)n + 3);
}

/** The link's handshake secrets, this end's then the peer's, and the transport parameters
 *  under them. */
static int install_handshake(path *p, const uint8_t *secrets) {
  level_keys l;
  ngtcp2_crypto_ctx c = crypto_ctx();
  if (level_keys_of(secrets, &l)) return -1;
  ngtcp2_conn_set_crypto_ctx(p->conn, &c);
  if (ngtcp2_conn_install_rx_handshake_key(p->conn, &l.aead[1], l.iv[1], 12, &l.hp[1])) return -1;
  // The server's own parameters are complete once its handshake keys are in.
  if (ngtcp2_conn_install_tx_handshake_key(p->conn, &l.aead[0], l.iv[0], 12, &l.hp[0])) return -1;
  return submit_params(p, NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE);
}

/** The link's session keys, this end's then the peer's, as the 1-RTT secrets. */
static int install_data(path *p, const uint8_t *secrets) {
  level_keys l;
  if (level_keys_of(secrets, &l)) return -1;
  if (ngtcp2_conn_install_rx_key(p->conn, secrets + 32, 32, &l.aead[1], l.iv[1], 12, &l.hp[1])) return -1;
  return ngtcp2_conn_install_tx_key(p->conn, secrets, 32, &l.aead[0], l.iv[0], 12, &l.hp[0]);
}

/** The handshake is over once the link has its session keys and the peer's parameters are
 *  in, whichever comes last: the 1-RTT keys go in then, as TLS puts them in at its Finished,
 *  so no 1-RTT packet is read before the peer's parameters are. */
static int complete(path *p) {
  if (p->completed || !p->have_keys || !p->have_params) return 0;
  p->completed = 1;
  int rv = install_data(p, p->keys);
  crypto_wipe(p->keys, sizeof p->keys);
  if (rv) return rv;
  ngtcp2_conn_tls_handshake_completed(p->conn);
  return 0;
}

// ── the handshake data ───────────────────────────────────────────────────────

// Each level's CRYPTO data is a run of `[kind u8][len u16][body]`: kind 1 a message of the
// link's, which goes up to it, and kind 2 this end's transport parameters. The client's first
// message goes at Initial and its later ones at Handshake; the server's one at Initial.
//
// Each end's parameters cross at Handshake, under the link's keys. The client's cross at
// Initial too, as TLS's ClientHello carries them, since the server settles its QUIC version
// on them before it sends its first Handshake packet; it takes them there, and holds the
// handshake open until the same bytes come again at Handshake.
enum { HS_LINK = 1, HS_PARAMS = 2 };

/** A run of parameters, as the server holds the client's Initial ones to check. */
static void params_hash(uint8_t out[32], const uint8_t *b, size_t n) { crypto_blake2b(out, 32, b, n); }

static int submit_link(path *p, const uint8_t *msg, size_t n) {
  uint8_t b[HS_MAX];
  if (n > sizeof b - 3) return -1;
  b[0] = HS_LINK, b[1] = (uint8_t)(n >> 8), b[2] = (uint8_t)n;
  memcpy(b + 3, msg, n);
  ngtcp2_encryption_level lv = !p->server && p->hs_sent++ > 0 ? NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE
                                                               : NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  return ngtcp2_conn_submit_crypto_data(p->conn, lv, b, n + 3);
}

#define FAIL(x) do { if ((x) != 0) return NGTCP2_ERR_CALLBACK_FAILURE; } while (0)

static int recv_crypto_data(ngtcp2_conn *conn, ngtcp2_encryption_level lv, uint64_t off, const uint8_t *data,
                            size_t n, void *ud) {
  path *p = ud;
  if (lv > NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE || n > HS_MAX - p->hs_len[lv]) return NGTCP2_ERR_CALLBACK_FAILURE;
  uint8_t *m = p->hs[lv];
  memcpy(m + p->hs_len[lv], data, n);
  p->hs_len[lv] += n;
  size_t at = 0;
  while (p->hs_len[lv] - at >= 3) {
    size_t len = (size_t)m[at + 1] << 8 | m[at + 2];
    if (p->hs_len[lv] - at - 3 < len) break;
    const uint8_t *body = m + at + 3;
    uint8_t h[32];
    if (m[at] == HS_PARAMS && lv == NGTCP2_ENCRYPTION_LEVEL_INITIAL && p->server && !p->initial_params) {
      FAIL(ngtcp2_conn_decode_and_set_remote_transport_params(conn, body, len));
      params_hash(p->params, body, len);
      p->initial_params = 1;
    } else if (m[at] == HS_PARAMS && lv == NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE && !p->have_params) {
      if (p->server) {
        params_hash(h, body, len);
        if (!p->initial_params || crypto_verify32(h, p->params)) return NGTCP2_ERR_CALLBACK_FAILURE;
      } else {
        FAIL(ngtcp2_conn_decode_and_set_remote_transport_params(conn, body, len));
      }
      p->have_params = 1;
    } else if (m[at] == HS_LINK && !p->completed) {
      if (len + 4 > sizeof p->hs_up - p->hs_up_len) return NGTCP2_ERR_CALLBACK_FAILURE;
      uint8_t *u = p->hs_up + p->hs_up_len;
      u[0] = (uint8_t)(len >> 24), u[1] = (uint8_t)(len >> 16), u[2] = (uint8_t)(len >> 8), u[3] = (uint8_t)len;
      memcpy(u + 4, body, len);
      p->hs_up_len += len + 4;
    } else {
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    at += 3 + len;
  }
  memmove(m, m + at, p->hs_len[lv] - at);
  p->hs_len[lv] -= at;
  FAIL(complete(p));
  return 0;
}

// ── packet protection ────────────────────────────────────────────────────────

static int encrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_aead_ctx *ctx,
                      const uint8_t *pt, size_t n, const uint8_t *nonce, size_t nlen, const uint8_t *aad,
                      size_t alen) {
  crypto_aead_ctx c;
  crypto_aead_init_ietf(&c, ctx->native_handle, nonce);
  crypto_aead_write(&c, dest, dest + n, aad, alen, pt, n);
  crypto_wipe(&c, sizeof c);
  return 0;
}

/** Opens into `dest`, or leaves it as it was: the tag is checked first. */
static int decrypt_cb(uint8_t *dest, const ngtcp2_crypto_aead *aead, const ngtcp2_crypto_aead_ctx *ctx,
                      const uint8_t *ct, size_t n, const uint8_t *nonce, size_t nlen, const uint8_t *aad,
                      size_t alen) {
  if (n < 16) return NGTCP2_ERR_DECRYPT;
  crypto_aead_ctx c;
  crypto_aead_init_ietf(&c, ctx->native_handle, nonce);
  int bad = crypto_aead_read(&c, dest, ct + n - 16, aad, alen, ct, n - 16);
  crypto_wipe(&c, sizeof c);
  return bad ? NGTCP2_ERR_DECRYPT : 0;
}

/** RFC 9001 §5.4.4: the counter is the sample's first four bytes, little-endian, the nonce
 *  the other twelve. */
static int hp_mask_cb(uint8_t *dest, const ngtcp2_crypto_cipher *hp, const ngtcp2_crypto_cipher_ctx *ctx,
                      const uint8_t *sample) {
  static const uint8_t zero[NGTCP2_HP_MASKLEN];
  uint32_t ctr = sample[0] | sample[1] << 8 | sample[2] << 16 | (uint32_t)sample[3] << 24;
  crypto_chacha20_ietf(dest, zero, NGTCP2_HP_MASKLEN, ctx->native_handle, sample + 4, ctr);
  return 0;
}

/** The next 1-RTT keys, which ngtcp2 asks for whenever it updates them: each secret
 *  ratcheted forward, so an update leaves no way back. */
static int update_key_cb(ngtcp2_conn *conn, uint8_t *rx_secret, uint8_t *tx_secret, ngtcp2_crypto_aead_ctx *rx_ctx,
                         uint8_t *rx_iv, ngtcp2_crypto_aead_ctx *tx_ctx, uint8_t *tx_iv, const uint8_t *cur_rx,
                         const uint8_t *cur_tx, size_t len, void *ud) {
  kdf(tx_secret, cur_tx, "seedkernel-quic-update-v1");
  kdf(rx_secret, cur_rx, "seedkernel-quic-update-v1");
  iv_of(tx_iv, tx_secret);
  iv_of(rx_iv, rx_secret);
  tx_ctx->native_handle = key_of(tx_secret, "seedkernel-quic-key-v1");
  rx_ctx->native_handle = key_of(rx_secret, "seedkernel-quic-key-v1");
  return tx_ctx->native_handle && rx_ctx->native_handle ? 0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

static void delete_aead_cb(ngtcp2_conn *conn, ngtcp2_crypto_aead_ctx *c, void *ud) {
  if (c->native_handle) crypto_wipe(c->native_handle, 32);
  free(c->native_handle);
}

static void delete_cipher_cb(ngtcp2_conn *conn, ngtcp2_crypto_cipher_ctx *c, void *ud) {
  if (c->native_handle) crypto_wipe(c->native_handle, 32);
  free(c->native_handle);
}

// ── Retry ────────────────────────────────────────────────────────────────────

// A listener answers a stranger's first Initial with a Retry, and a path opens only for an
// Initial that echoes its token from the address the Retry went to: a spoofed source never
// sees the token, so it costs the listener one small answer and no state, and the path is
// validated from its first packet. The token is `[odcid len u8][odcid][issued f64]`, and the
// Retry's source ID, which the client's next Initial is addressed to, is keyed over the
// token and the address: that ID is the token's MAC.

/** How long a Retry token stands, in the realm's milliseconds. */
#define TOKEN_MS 10000.0
/** The Initials one screen names at most: a `datagrams` event's worth. */
#define SCREEN_MAX 2048

/** The Retry integrity key: fixed, as RFC 9001's is, since a Retry proves only that it was
 *  not damaged; the server's parameters, under the link's keys, say whether it sent one. */
static void retry_key(uint8_t k[32]) {
  static const uint8_t fixed[32];
  kdf(k, fixed, "seedkernel-quic-retry-v1");
}

/** The Retry source ID for `token` sent to `from`, under the listener's key. */
static void retry_cid(ngtcp2_cid *cid, const uint8_t key[32], const ngtcp2_sockaddr_union *from, const uint8_t *token,
                      size_t n) {
  uint8_t h[32];
  crypto_blake2b_ctx c;
  crypto_blake2b_keyed_init(&c, 32, key, 32);
  crypto_blake2b_update(&c, (const uint8_t *)from, sizeof *from);
  crypto_blake2b_update(&c, token, n);
  crypto_blake2b_final(&c, h);
  ngtcp2_cid_init(cid, h, 16);
}

/** Whether Initial `hd` from `from` carries a token of this listener's, fresh, and is
 *  addressed to that token's Retry source ID; if so, `odcid` is the ID the client first
 *  chose. */
static int token_ok(const uint8_t key[32], const ngtcp2_sockaddr_union *from, const ngtcp2_pkt_hd *hd, double now_ms,
                    ngtcp2_cid *odcid) {
  const uint8_t *t = hd->token;
  if (hd->tokenlen < 9 || t[0] > NGTCP2_MAX_CIDLEN || hd->tokenlen != (size_t)t[0] + 9) return 0;
  reader r = {t + 1 + t[0], 8, 0, 0};
  double issued = f64(&r);
  if (!(issued <= now_ms && now_ms - issued <= TOKEN_MS)) return 0;
  ngtcp2_cid want;
  retry_cid(&want, key, from, t, hd->tokenlen);
  if (hd->dcid.datalen != 16 || crypto_verify16(hd->dcid.data, want.data)) return 0;
  ngtcp2_cid_init(odcid, t + 1, t[0]);
  return 1;
}

/** `[now f64][key 32][socket u32][batch]`, the batch the listening socket's datagrams no
 *  path answers to: each Initial without a token is answered with a Retry, and each whose
 *  token stands is named, by its place in the batch, for a path to open for. Answers
 *  `[n u16]([index u16])*[sends]`. */
static int op_screen(reader *r) {
  double now_ms = f64(r);
  const uint8_t *key = take(r, 32);
  uint32_t socket = u32(r);
  if (r->bad) return -1;
  uint8_t k[32];
  retry_key(k);
  ngtcp2_crypto_aead aead = {NULL, 16};
  ngtcp2_crypto_aead_ctx ctx = {k};
  // The sends go behind room for every name, which close up on them at the end.
  size_t n = 0, sends = 2 + 2 * SCREEN_MAX;
  out_at = sends;
  for (uint32_t i = 0; r->at < r->n; i++) {
    ngtcp2_sockaddr_union from;
    if (!read_addr(r, &from)) return -1;
    size_t len = u16(r);
    const uint8_t *pkt = take(r, len);
    if (r->bad) return -1;
    ngtcp2_pkt_hd hd;
    ngtcp2_cid odcid;
    if (ngtcp2_accept(&hd, pkt, len) != 0) continue;
    if (hd.tokenlen > 0) {
      if (n < SCREEN_MAX && token_ok(key, &from, &hd, now_ms, &odcid)) {
        answer[2 + 2 * n] = (uint8_t)(i >> 8), answer[3 + 2 * n] = (uint8_t)i;
        n++;
      }
      continue;
    }
    uint8_t token[1 + NGTCP2_MAX_CIDLEN + 8], buf[256];
    size_t tn = 1 + hd.dcid.datalen + 8;
    token[0] = (uint8_t)hd.dcid.datalen;
    memcpy(token + 1, hd.dcid.data, hd.dcid.datalen);
    uint64_t v;
    memcpy(&v, &now_ms, 8);
    for (int b = 7; b >= 0; b--, v >>= 8) token[1 + hd.dcid.datalen + b] = (uint8_t)v;
    ngtcp2_cid scid;
    retry_cid(&scid, key, &from, token, tn);
    ngtcp2_ssize w = ngtcp2_pkt_write_retry(buf, sizeof buf, hd.version, &hd.scid, &scid, &hd.dcid, token, tn,
                                            encrypt_cb, &aead, &ctx);
    if (w > 0 && out_at + 1600 <= SEND_MAX) put_send(socket, &from, buf, (size_t)w);
  }
  crypto_wipe(k, sizeof k);
  answer[0] = (uint8_t)(n >> 8), answer[1] = (uint8_t)n;
  memmove(answer + 2 + 2 * n, answer + sends, out_at - sends);
  return (int)(2 + 2 * n + out_at - sends);
}

// ── what ngtcp2 asks of the path ─────────────────────────────────────────────

/** Randomness, drawn from the seed `OP_OPEN` hands in. */
static void rand_cb(uint8_t *dest, size_t n, const ngtcp2_rand_ctx *rc) {
  path *p = rc->native_handle;
  memset(dest, 0, n);
  p->rng_ctr = crypto_chacha20_ietf(dest, dest, n, p->seed, (const uint8_t *)"seedkernel-q", p->rng_ctr);
}

/** A connection ID, and its stateless reset token keyed by the path's own secret. */
static int new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token, size_t len, void *ud) {
  path *p = ud;
  ngtcp2_rand_ctx rc = {p};
  uint8_t key[32], t[32];
  rand_cb(cid->data, len, &rc);
  cid->datalen = len;
  kdf(key, p->seed, "seedkernel-quic-reset-v1");
  crypto_blake2b_keyed(t, 32, key, 32, cid->data, len);
  memcpy(token->data, t, sizeof token->data);
  p->cids_dirty = 1;
  return 0;
}

static int remove_cid_cb(ngtcp2_conn *conn, const ngtcp2_cid *cid, void *ud) {
  ((path *)ud)->cids_dirty = 1;
  return 0;
}

static int path_challenge_cb(ngtcp2_conn *conn, ngtcp2_path_challenge_data *d, void *ud) {
  ngtcp2_rand_ctx rc = {ud};
  rand_cb(d->data, sizeof d->data, &rc);
  return 0;
}

static int client_initial_cb(ngtcp2_conn *conn, void *ud) {
  FAIL(install_initial(ud));
  FAIL(submit_params(ud, NGTCP2_ENCRYPTION_LEVEL_INITIAL));
  return 0;
}

static int recv_client_initial_cb(ngtcp2_conn *conn, const ngtcp2_cid *dcid, void *ud) {
  FAIL(install_initial(ud));
  return 0;
}

/** A listener's Retry: the Initial keys are fixed, not drawn from the new ID, so they go in
 *  again as they were. */
static int recv_retry_cb(ngtcp2_conn *conn, const ngtcp2_pkt_hd *hd, void *ud) {
  FAIL(install_initial(ud));
  return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t id, void *ud) {
  path *p = ud;
  if (p->rstream < 0) p->rstream = id;
  return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t id, uint64_t off, const uint8_t *d,
                               size_t n, void *ud, void *sud) {
  path *p = ud;
  if (id != p->rstream) return 0;
  if (p->rhead + p->rlen + n > p->rcap) {
    memmove(p->rbuf, p->rbuf + p->rhead, p->rlen);
    p->rhead = 0;
    if (p->rlen + n > p->rcap) {
      size_t cap = p->rcap ? p->rcap : 64 * 1024;
      while (cap < p->rlen + n) cap *= 2;
      uint8_t *b = realloc(p->rbuf, cap);
      if (!b) return NGTCP2_ERR_CALLBACK_FAILURE;
      p->rbuf = b;
      p->rcap = cap;
    }
  }
  memcpy(p->rbuf + p->rhead + p->rlen, d, n);
  p->rlen += n;
  return 0;
}

static void free_chunk(path *p, uint64_t c) {
  free(p->chunk[c % CHUNKS]);
  p->chunk[c % CHUNKS] = NULL;
}

/** Frees each chunk once it is wholly acked, and the last one once everything written is,
 *  so an idle path holds none. A chunk's slot is not written again until it is free
 *  (`accept_write`). */
static int acked_cb(ngtcp2_conn *conn, int64_t id, uint64_t off, uint64_t n, void *ud, void *sud) {
  path *p = ud;
  if (id != p->stream || off + n <= p->acked) return 0;
  for (uint64_t c = p->acked / CHUNK; c < (off + n) / CHUNK; c++) {
    free_chunk(p, c);
  }
  p->acked = off + n;
  if (p->acked == p->end) free_chunk(p, p->acked / CHUNK);
  return 0;
}

static void config(path *p, ngtcp2_callbacks *cb, ngtcp2_settings *st, ngtcp2_transport_params *tp, ngtcp2_tstamp now) {
  // QUIC's floor to begin with, and PLPMTUD up to 1452: Ethernet's 1500 less IPv6's and
  // UDP's headers.
  static const uint16_t probes[] = {1452};
  memset(cb, 0, sizeof *cb);
  cb->client_initial = p->server ? NULL : client_initial_cb;
  cb->recv_client_initial = p->server ? recv_client_initial_cb : NULL;
  cb->recv_crypto_data = recv_crypto_data;
  cb->encrypt = encrypt_cb;
  cb->decrypt = decrypt_cb;
  cb->hp_mask = hp_mask_cb;
  cb->recv_retry = recv_retry_cb;
  cb->rand = rand_cb;
  cb->get_new_connection_id2 = new_cid_cb;
  cb->remove_connection_id = remove_cid_cb;
  cb->update_key = update_key_cb;
  cb->delete_crypto_aead_ctx = delete_aead_cb;
  cb->delete_crypto_cipher_ctx = delete_cipher_cb;
  cb->get_path_challenge_data2 = path_challenge_cb;
  cb->stream_open = stream_open_cb;
  cb->recv_stream_data = recv_stream_data_cb;
  cb->acked_stream_data_offset = acked_cb;
  ngtcp2_settings_default(st);
  st->initial_ts = now;
  st->rand_ctx.native_handle = p;
  st->max_tx_udp_payload_size = 1452;
  st->pmtud_probes = probes;
  st->pmtud_probeslen = 1;
  st->max_window = WINDOW;
  st->max_stream_window = WINDOW;
  // BBR, not CUBIC: one path stands where TCP opens 8 connections, and at each loss one CUBIC
  // flow gives up 30% of its rate where 8 give up 4% of theirs together. On a WAN pair CUBIC
  // was slower than TCP's 8 connections, BBR faster.
  st->cc_algo = NGTCP2_CC_ALGO_BBR;
  ngtcp2_transport_params_default(tp);
  tp->initial_max_streams_bidi = 0;
  tp->initial_max_streams_uni = 1;
  tp->initial_max_stream_data_uni = WINDOW;
  tp->initial_max_data = WINDOW;
  // Something every 5 s keeps the path's NAT mappings open, and 30 s of silence ends it.
  tp->max_idle_timeout = 30 * NGTCP2_SECONDS;
  // Every QUIC packet has the fixed bit, which is how udp.js tells them from its probes.
  tp->grease_quic_bit = 0;
}

static path *find(uint32_t id) {
  for (path *p = paths; p; p = p->next) {
    if (p->id == id) return p;
  }
  return NULL;
}

static void drop(uint32_t id) {
  for (path **pp = &paths; *pp; pp = &(*pp)->next) {
    if ((*pp)->id != id) continue;
    path *p = *pp;
    *pp = p->next;
    if (p->conn) ngtcp2_conn_del(p->conn);
    free(p->rbuf);
    for (uint64_t c = 0; c < CHUNKS; c++) {
      free_chunk(p, c);
    }
    crypto_wipe(p, sizeof *p);
    free(p);
    return;
  }
}

/** The local end of a path: the socket's, which the module never learns, in the peer's
 *  family. */
static ngtcp2_path path_of(path *p, const ngtcp2_sockaddr_union *remote) {
  memset(&p->local, 0, sizeof p->local);
  p->local.sa.sa_family = remote->sa.sa_family;
  return (ngtcp2_path){{&p->local.sa, addr_len(&p->local)}, {(ngtcp2_sockaddr *)&remote->sa, addr_len(remote)}, NULL};
}

/** `[path u32][client u8][now f64][seed 32][socket u32][peer]([listener key 32])`, the
 *  peer's address the one the client dials and the only one the server takes the connection
 *  from. A server given a listener's key takes it only from an Initial that echoes that
 *  listener's Retry (`token_ok`). Answers `[ok u8]`. */
static int op_open(reader *r) {
  uint32_t id = u32(r);
  int client = u8(r) == 1;
  ngtcp2_tstamp now = ts_of(f64(r));
  const uint8_t *seed = take(r, 32);
  uint32_t socket = u32(r);
  ngtcp2_sockaddr_union remote;
  if (r->bad || !read_addr(r, &remote)) return -1;
  const uint8_t *listen_key = !client && r->at < r->n ? take(r, 32) : NULL;
  if (r->bad) return -1;
  drop(id);
  path *p = calloc(1, sizeof *p);
  if (!p) return -1;
  p->id = id;
  p->socket = socket;
  p->server = !client;
  p->stream = p->rstream = -1;
  p->peer = remote;
  memcpy(p->seed, seed, 32);
  if (listen_key) {
    p->listener = 1;
    memcpy(p->listen_key, listen_key, 32);
  }
  p->next = paths;
  paths = p;
  if (client) {
    ngtcp2_callbacks cb;
    ngtcp2_settings st;
    ngtcp2_transport_params tp;
    ngtcp2_cid dcid, scid;
    ngtcp2_rand_ctx rc = {p};
    config(p, &cb, &st, &tp, now);
    dcid.datalen = scid.datalen = 16;
    rand_cb(dcid.data, 16, &rc);
    rand_cb(scid.data, 16, &rc);
    ngtcp2_path path = path_of(p, &remote);
    uint8_t *rk = malloc(32);
    if (rk) retry_key(rk);
    if (!rk || ngtcp2_conn_client_new(&p->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &cb, &st, &tp, NULL, p)) {
      free(rk);
      p->conn = NULL;
      drop(id);
      return -1;
    }
    // A listener's Retry is checked under it; it goes with the connection (`delete_aead_cb`).
    ngtcp2_conn_set_retry_aead(p->conn, &(ngtcp2_crypto_aead){NULL, 16}, &(ngtcp2_crypto_aead_ctx){rk});
    ngtcp2_conn_set_keep_alive_timeout(p->conn, 5 * NGTCP2_SECONDS);
  }
  answer[0] = 1;
  return 1;
}

/** The server's connection, from the client's first Initial, from the peer's address
 *  alone: both are as `read_addr` spells them, so the bytes compare. A listener's is from
 *  an Initial that echoes its Retry, which validates the address. */
static int accept_from(path *p, const ngtcp2_sockaddr_union *from, const uint8_t *pkt, size_t n, double now_ms) {
  ngtcp2_tstamp now = ts_of(now_ms);
  ngtcp2_pkt_hd hd;
  ngtcp2_cid odcid;
  if (memcmp(from, &p->peer, sizeof *from) || ngtcp2_accept(&hd, pkt, n) != 0) return -1;
  if (p->listener && !token_ok(p->listen_key, from, &hd, now_ms, &odcid)) return -1;
  ngtcp2_callbacks cb;
  ngtcp2_settings st;
  ngtcp2_transport_params tp;
  ngtcp2_cid scid;
  ngtcp2_rand_ctx rc = {p};
  config(p, &cb, &st, &tp, now);
  tp.original_dcid = p->listener ? odcid : hd.dcid;
  tp.original_dcid_present = 1;
  if (p->listener) {
    tp.retry_scid = hd.dcid;
    tp.retry_scid_present = 1;
    st.token = hd.token;
    st.tokenlen = hd.tokenlen;
    st.token_type = NGTCP2_TOKEN_TYPE_RETRY;
  }
  scid.datalen = 16;
  rand_cb(scid.data, 16, &rc);
  ngtcp2_path path = path_of(p, from);
  if (ngtcp2_conn_server_new(&p->conn, &hd.scid, &scid, &path, hd.version, &cb, &st, &tp, NULL, p)) {
    p->conn = NULL;
    return -1;
  }
  ngtcp2_conn_set_keep_alive_timeout(p->conn, 5 * NGTCP2_SECONDS);
  p->cids_dirty = 1;
  return 0;
}

/** The connection is over: tell the peer, if `rv` is ngtcp2's own error, and stop. */
static void end_conn(path *p, int rv, ngtcp2_tstamp now) {
  if (p->closed) return;
  p->closed = 1;
  p->events |= E_CLOSED;
  if (!p->conn || rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_IDLE_CLOSE || rv == NGTCP2_ERR_DROP_CONN) return;
  ngtcp2_ccerr ccerr;
  ngtcp2_path_storage ps;
  uint8_t buf[1500];
  if (rv) ngtcp2_ccerr_set_liberr(&ccerr, rv, NULL, 0);
  else ngtcp2_ccerr_default(&ccerr);
  ngtcp2_path_storage_zero(&ps);
  ngtcp2_ssize w = ngtcp2_conn_write_connection_close(p->conn, &ps.path, NULL, buf, sizeof buf, &ccerr, now);
  if (w > 0) {
    ngtcp2_sockaddr_union to;
    memcpy(&to, ps.path.remote.addr, ps.path.remote.addrlen);
    for (int i = 0; i < CLOSE_COPIES; i++) {
      put_send(p->socket, &to, buf, (size_t)w);
    }
  }
}

/** One datagram into the connection, which ends it if ngtcp2 says so. */
static void read_one(path *p, const ngtcp2_sockaddr_union *from, const uint8_t *pkt, size_t len, ngtcp2_tstamp now) {
  ngtcp2_path path = path_of(p, from);
  int rv = ngtcp2_conn_read_pkt(p->conn, &path, NULL, pkt, len, now);
  if (rv == NGTCP2_ERR_DRAINING || (rv && ngtcp2_err_is_fatal(rv))) end_conn(p, rv, now);
}

/** The held datagrams, read again in the order they came (`held`). */
static void replay(path *p, ngtcp2_tstamp now) {
  int n = p->nheld < HELD_MAX ? p->nheld : HELD_MAX, first = p->nheld - n;
  for (int i = 0; i < n && !p->closed; i++) {
    int at = (first + i) % HELD_MAX;
    read_one(p, &p->held[at].from, p->held[at].b, p->held[at].len, now);
  }
}

/** Takes what was written, as much as there is room for: up to `QUEUE_MAX` not yet sent,
 *  and never into a chunk's slot while an older chunk in it is not wholly acked. */
static uint32_t accept_write(path *p, const uint8_t *w, size_t n) {
  uint64_t limit = p->acked / CHUNK * CHUNK + WINDOW;
  if (p->sent + QUEUE_MAX < limit) limit = p->sent + QUEUE_MAX;
  size_t done = 0;
  while (done < n && p->end < limit) {
    uint8_t **c = &p->chunk[(p->end / CHUNK) % CHUNKS];
    if (!*c && !(*c = malloc(CHUNK))) break;
    size_t at = (size_t)(p->end % CHUNK), run = CHUNK - at;
    if (run > n - done) run = n - done;
    if (run > limit - p->end) run = (size_t)(limit - p->end);
    memcpy(*c + at, w + done, run);
    done += run;
    p->end += run;
  }
  return (uint32_t)done;
}

/** The datagrams to send, up to `SEND_MAX` of the answer; whether that filled it. Unpaced:
 *  ngtcp2 paces behind every packet, acks among them, so a response would wait on a realm
 *  wake behind its own ack, and that measured 5-35% slower on every bench. */
static int transmit(path *p, ngtcp2_tstamp now, size_t sends) {
  uint8_t buf[1500];
  int blocked = 0;
  for (;;) {
    if (out_at - sends >= SEND_MAX) return 1;
    // Each end opens its own stream once the handshake is over.
    if (p->stream < 0 && p->completed) ngtcp2_conn_open_uni_stream(p->conn, &p->stream, NULL);
    ngtcp2_vec v[2];
    size_t nv = 0;
    int stream = !blocked && p->stream >= 0 && (p->sent < p->end || (p->fin_wanted && !p->fin_sent));
    if (stream && p->sent < p->end) {
      // A packet is less than a chunk, so it takes from two at most.
      size_t at = (size_t)(p->sent % CHUNK), n = (size_t)(p->end - p->sent);
      size_t run = CHUNK - at < n ? CHUNK - at : n;
      v[nv++] = (ngtcp2_vec){p->chunk[(p->sent / CHUNK) % CHUNKS] + at, run};
      if (run < n) v[nv++] = (ngtcp2_vec){p->chunk[(p->sent / CHUNK + 1) % CHUNKS], n - run < CHUNK ? n - run : CHUNK};
    }
    uint32_t flags = stream && p->fin_wanted ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
    ngtcp2_path_storage ps;
    ngtcp2_ssize took = -1;
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_ssize w = ngtcp2_conn_writev_stream(p->conn, &ps.path, NULL, buf, sizeof buf, &took, flags,
                                               stream ? p->stream : -1, v, nv, now);
    if (w == NGTCP2_ERR_STREAM_DATA_BLOCKED || w == NGTCP2_ERR_STREAM_SHUT_WR || w == NGTCP2_ERR_STREAM_NOT_FOUND) {
      blocked = 1;
      continue;
    }
    if (w < 0) {
      end_conn(p, (int)w, now);
      return 0;
    }
    if (took >= 0) {
      p->sent += (uint64_t)took;
      if (flags && p->sent == p->end) p->fin_sent = 1;
    }
    if (w == 0) return 0;
    ngtcp2_sockaddr_union to;
    memcpy(&to, ps.path.remote.addr, ps.path.remote.addrlen);
    put_send(p->socket, &to, buf, (size_t)w);
  }
}

/** `[path u32][now f64][flags u8][read max u32]([handshake secrets 64] with F_HS_KEYS)
 *  ([session keys 64] with F_KEYS)[n u8]([len u32][message])*[write len u32][write]
 *  ([len u32][batch])*`, answered `[events u8][accepted u32][due f64][read len u32]
 *  [handshake len u32][ids u8][read]([len u32][message])*([id u32])*[sends]`.
 *
 *  The secrets are this end's then the peer's. The messages are the link's handshake, both
 *  ways. A batch is the path socket's datagrams as the host's `datagrams` event carries
 *  them, `[n u8][ip n][port u16][len u16][bytes]` each, of which the module takes the QUIC
 *  ones; `sends` is the datagrams to send as `link/udpSend` takes them. `due` is when to
 *  call again, in the realm's milliseconds, or -1 for no timer. A listener's path names
 *  the connection IDs it answers to whenever they change, each by its first four bytes,
 *  which udp.js routes the listening socket's datagrams by. */
static int op_turn(reader *r) {
  uint32_t id = u32(r);
  double now_ms = f64(r);
  uint32_t flags = u8(r), read_max = u32(r);
  const uint8_t *hs_keys = flags & F_HS_KEYS ? take(r, 64) : NULL;
  const uint8_t *keys = flags & F_KEYS ? take(r, 64) : NULL;
  uint32_t msgs = u8(r);
  const uint8_t *msg[4];
  size_t msg_len[4];
  if (msgs > 4) return -1;
  for (uint32_t i = 0; i < msgs; i++) {
    msg_len[i] = u32(r);
    msg[i] = take(r, msg_len[i]);
  }
  size_t write_len = u32(r);
  const uint8_t *write = take(r, write_len);
  if (r->bad) return -1;
  ngtcp2_tstamp now = ts_of(now_ms);
  path *p = find(id);
  uint32_t accepted = 0;
  if (read_max > READ_MAX) read_max = READ_MAX;
  out_at = 0;
  put("\0\0\0\0\0", 5);
  put_f64_at(out_at, -1);
  out_at += 8;
  put("\0\0\0\0\0\0\0\0\0", 9);
  if (!p) {
    answer[0] = E_CLOSED;
    return (int)out_at;
  }
  size_t sends = out_at;

  // What came in: the batches' QUIC datagrams.
  while (r->at < r->n && !p->closed) {
    uint32_t n = u32(r);
    const uint8_t *batch = take(r, n);
    if (r->bad) return -1;
    reader b = {batch, n, 0, 0};
    while (b.at < b.n && !p->closed) {
      ngtcp2_sockaddr_union from;
      if (!read_addr(&b, &from)) return -1;
      size_t len = u16(&b);
      const uint8_t *pkt = take(&b, len);
      if (b.bad) return -1;
      if (len == 0 || !(pkt[0] & 0x40)) continue;
      if (!p->conn && (!p->server || accept_from(p, &from, pkt, len, now_ms))) continue;
      if (!p->completed && len <= sizeof p->held[0].b) {
        int i = p->nheld++ % HELD_MAX;
        p->held[i].from = from;
        p->held[i].len = len;
        memcpy(p->held[i].b, pkt, len);
      }
      read_one(p, &from, pkt, len, now);
    }
  }

  // The link's keys go in before its messages: the client's last message is a Handshake
  // one, which needs them, and the server's one stays an Initial one regardless.
  if (p->conn && !p->closed) {
    int bad = hs_keys && install_handshake(p, hs_keys);
    if (hs_keys && !bad) replay(p, now);
    if (keys && !bad) {
      memcpy(p->keys, keys, sizeof p->keys);
      p->have_keys = 1;
    }
    for (uint32_t i = 0; i < msgs && !bad; i++) bad = submit_link(p, msg[i], msg_len[i]);
    int was = p->completed;
    if (!bad && !p->closed) bad = complete(p);
    if (bad) end_conn(p, NGTCP2_ERR_INTERNAL, now);
    else if (!was && p->completed) replay(p, now);
  }
  if (p->completed) p->nheld = 0;
  if (p->conn && !p->closed) {
    accepted = accept_write(p, write, write_len);
    if (flags & F_FIN) p->fin_wanted = 1;
    if (flags & F_CLOSE) {
      end_conn(p, 0, now);
    } else if (ngtcp2_conn_get_expiry(p->conn) <= now) {
      int rv = ngtcp2_conn_handle_expiry(p->conn, now);
      if (rv) end_conn(p, rv, now);
    }
  }

  // What the reader takes, only once the handshake is over, moves the windows on before
  // this turn's packets go, so they carry the news.
  size_t read = !p->completed ? 0 : p->rlen < read_max ? p->rlen : read_max;
  int full = 0;
  if (p->conn && !p->closed) {
    if (read) {
      ngtcp2_conn_extend_max_stream_offset(p->conn, p->rstream, read);
      ngtcp2_conn_extend_max_offset(p->conn, read);
    }
    full = transmit(p, now, sends);
  }

  // A listener's connection IDs, when they changed: at most a pool's worth.
  ngtcp2_cid cids[8];
  size_t ids = 0;
  if (p->listener && p->cids_dirty && p->conn && !p->closed && ngtcp2_conn_get_scid(p->conn, NULL) <= 8) {
    ids = ngtcp2_conn_get_scid(p->conn, cids);
    p->cids_dirty = 0;
  }

  // The answer's head, what was read, the link's messages and the IDs, then the datagrams
  // already in place behind them.
  size_t send_len = out_at - sends, hs = p->hs_up_len;
  memmove(answer + sends + read + hs + 4 * ids, answer + sends, send_len);
  if (read) {
    memcpy(answer + sends, p->rbuf + p->rhead, read);
    p->rhead += read;
    p->rlen -= read;
  }
  // A path with nothing to hand over holds no buffer for it.
  if (p->rlen == 0 && p->rbuf) {
    free(p->rbuf);
    p->rbuf = NULL;
    p->rhead = p->rcap = 0;
  }
  memcpy(answer + sends + read, p->hs_up, hs);
  p->hs_up_len = 0;
  for (size_t i = 0; i < ids; i++) {
    const uint8_t *c = cids[i].data;
    put_u32_at(sends + read + hs + 4 * i, (uint32_t)c[0] << 24 | (uint32_t)c[1] << 16 | (uint32_t)c[2] << 8 | c[3]);
  }
  if (p->completed && p->rlen > 0) p->events |= E_MORE;
  if (!p->finished_told && p->fin_sent && p->acked >= p->end) {
    p->finished_told = 1;
    p->events |= E_FINISHED;
  }
  out_at = sends + read + hs + 4 * ids + send_len;
  answer[0] = p->events;
  p->events = 0;
  put_u32_at(1, accepted);
  if (p->conn && !p->closed) {
    ngtcp2_tstamp due = ngtcp2_conn_get_expiry(p->conn);
    double ms = full ? now_ms : due == UINT64_MAX ? -1 : due <= now ? now_ms : now_ms + (double)(due - now) / 1e6;
    put_f64_at(5, ms);
  }
  put_u32_at(13, (uint32_t)read);
  put_u32_at(17, (uint32_t)hs);
  answer[21] = (uint8_t)ids;
  return (int)out_at;
}

/** One call: `[op u8]` and its body, answered in place. `OP_DROP [path u32]` forgets a path. */
__attribute__((export_name("handle"))) int32_t handle(int32_t len) {
  reader r = {scratch, len < 0 ? 0 : (size_t)len > SCRATCH_BYTES ? SCRATCH_BYTES : (size_t)len, 0, 0};
  int n;
  switch (u8(&r)) {
  case OP_OPEN:
    n = op_open(&r);
    break;
  case OP_TURN:
    n = op_turn(&r);
    break;
  case OP_DROP:
    drop(u32(&r));
    n = r.bad ? -1 : 0;
    break;
  case OP_SCREEN:
    n = op_screen(&r);
    break;
  default:
    n = -1;
  }
  if (n > 0) memcpy(scratch, answer, (size_t)n);
  return n;
}

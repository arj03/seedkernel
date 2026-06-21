package main

import _ "embed"

// hostNetRouteJS is the shared transport + routing core (net.ts Transport +
// net-route.ts NodeNetworkCore + net-link.ts PeerLink), bundled from
// build/host/{util,net,net-link,net-route}.js. It runs in QuickJS over a Go-backed
// ChannelFactory (engineNetworkJS, sock.go) that opens sockets through __net. This
// is the routing that used to live in net.go's NodeNetwork + Transport.
//
//go:embed host-netroute.gen.js
var hostNetRouteJS string

// hostWsJS is the shared WebSocket codec + channel, bundled from
// build/host/{util,ws/ws-codec,net-frame}.js. It runs in QuickJS and frames RFC
// 6455 over a raw Go byte stream (sock.go connectRaw/listenRaw) by driving the
// embedded ws.wasm through the __ws primitive (wsframe.go) — the same ws.wasm the
// node/bun WebAssembly backend uses, so framing is byte-identical. This replaces
// the hand-rolled Go RFC 6455 codec that used to live in ws.go.
//
//go:embed host-ws.gen.js
var hostWsJS string

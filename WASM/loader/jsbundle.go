package main

import _ "embed"

// hostNetLinkJS is the shared channel-identity handshake (net-link.ts → PeerLink),
// bundled from build/host/{util,net-link}.js. It drives the RawChannel the Go
// socket primitive (sock.go) exposes and signs the transcript via the `sodium`
// object — the Go peerLink in net.go is being replaced by this.
//
//go:embed host-netlink.gen.js
var hostNetLinkJS string

// hostNetRouteJS is the shared transport + routing core (net.ts Transport +
// net-route.ts NodeNetworkCore + net-link.ts PeerLink), bundled from
// build/host/{util,net,net-link,net-route}.js. It runs in QuickJS over a Go-backed
// ChannelFactory (engineNetworkJS, sock.go) that opens sockets through __net. This
// is the routing that used to live in net.go's NodeNetwork + Transport.
//
//go:embed host-netroute.gen.js
var hostNetRouteJS string

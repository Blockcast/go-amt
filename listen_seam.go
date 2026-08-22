//go:build linux || darwin

package amt

// listenMulticastUDP4 is the seam BOTH native-join call sites perform their v4
// group join through: MulticastConn.Open in conn.go and
// ManagedConn.dialNativeMulticast in managed_conn_native.go. Production always
// runs the real ListenMulticastUDP4; a test may wrap it to observe whether the
// join was ATTEMPTED, or replace it outright to control what the join delivers.
//
// Observing the attempt is the whole point of the wrapping form and it is not
// decoration. The guard on the plan-before-bind ordering has to answer "did Open
// touch the socket?", and there is no way to answer it from the outside
// afterwards. Inferring it from the bind FAILING does not work: a bogus
// interface makes the join fail on darwin but bind successfully on linux, and on
// the tunnel-handover path the socket is closed and the field set back to nil
// anyway — so on ubuntu-latest, the only platform cgo-test runs, "did it fail
// the right way" and "is the native conn still set" both answer identically
// whether or not the bind happened. A guard built on either is green under the
// mutation it exists to catch (Ally review on go-amt#49, after a first repair
// that looked correct on darwin and was vacuous on CI). A wrapper counts and
// delegates rather than stubbing, so what the test measures is Open's real
// behaviour and not the wrapper's.
//
// Replacing it outright is the other form, and it is what lets a switchover test
// exist at all. The real ListenMulticastUDP4 ends in IP_ADD_MEMBERSHIP, which a
// stock ubuntu-latest runner cannot satisfy — no multicast route, no
// CAP_NET_ADMIN — so a test that needs native delivery to start and stop ON
// DEMAND cannot go through it. A substitute returning a loopback socket the test
// also sends to gives the same *ipv4.PacketConn with real deadline semantics, so
// probeNativeTraffic is genuinely exercised rather than mocked out. See
// fakeNativeSource in fakenative_test.go.
//
// WHY THIS FILE: the var used to live in conn.go, which is tagged
// `(linux || darwin) && !ios && !android && cgo && !purego`. That put the seam
// behind cgo, so ManagedConn — selected by a *different* tag set
// (managed_conn_native.go is `linux || darwin`) — could not reach it and called
// ListenMulticastUDP4 directly. One path substitutable and the other not is the
// same asymmetry that let ManagedConn keep the BLO-28640 defect after
// MulticastConn was fixed; probe.go carries the matching note for the probe
// machinery. `linux || darwin` is the union of the two call sites' tags and is
// exactly where ListenMulticastUDP4 is declared for every GOOS in it
// (listen_multicast_linux.go for `linux && !android`, listen_multicast_darwin.go
// for `darwin && !ios`, listen_multicast_mobile.go for `android || ios`), so the
// seam is available wherever either caller is and declared nowhere it is not.
var listenMulticastUDP4 = ListenMulticastUDP4

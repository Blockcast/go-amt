//go:build (linux && !android) || (darwin && !ios)

package amt

// listenMulticastUDP6 is the v6 counterpart of the listenMulticastUDP4 seam in
// listen_seam.go, and exists for the same two reasons: a test can observe what
// MulticastConn.Open actually passes its v6 group join, and it can replace the
// join outright on a runner that cannot satisfy IPV6_ADD_MEMBERSHIP.
//
// Added by BLO-34983 so the control-flag guard covers both families. Leaving v6
// unsubstitutable while v4 had a seam is the same asymmetry listen_seam.go was
// written about — and v6 is the family with no headroom, so it is the one where
// an unguarded flag change actually costs a receiver.
//
// Tagged narrower than the v4 seam because ListenMulticastUDP6 is declared
// narrower: listen_multicast6_linux.go is `linux && !android` and
// listen_multicast6_darwin.go is `darwin && !ios`, and there is no v6
// counterpart to listen_multicast_mobile.go. That union is a superset of
// conn.go's tag, which is the only caller.
var listenMulticastUDP6 = ListenMulticastUDP6

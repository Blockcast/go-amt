package messages

/*
	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  V=0  |Type=6 |    Reserved   |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
~                     IP Multicast Packet                       ~
|                                                               |
+                - - - - - - - - - - - - - - - - - - - - - - - -+
|               :               :               :               :
+-+-+-+-+-+-+-+-+- - - - - - - - - - - - - - - - - - - - - - - -

	RFC7450 Figure 16: Multicast Data Message Format
*/
type MulticastDataMessage struct {
	Header
	Data []byte
}

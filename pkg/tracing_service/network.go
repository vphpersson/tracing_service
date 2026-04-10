package tracing_service

// IsIPv4MappedIPv6 checks if a 16-byte address is an IPv4-mapped IPv6 address (::ffff:x.x.x.x).
func IsIPv4MappedIPv6(addr [16]byte) bool {
	for i := 0; i < 10; i++ {
		if addr[i] != 0 {
			return false
		}
	}
	return addr[10] == 0xff && addr[11] == 0xff
}

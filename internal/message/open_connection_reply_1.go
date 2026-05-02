package message

import (
	"encoding/binary"
	"io"
)

type OpenConnectionReply1 struct {
	ServerGUID        int64
	ServerHasSecurity bool
	Cookie            uint32
	MTU               uint16
}

func (pk *OpenConnectionReply1) UnmarshalBinary(data []byte) error {
	if len(data) < 27 {
		return io.ErrUnexpectedEOF
	}
	// Magic: 16 bytes.
	pk.ServerGUID = int64(binary.BigEndian.Uint64(data[16:]))

	// Some anti-DDoS proxies (notably OVH) send a Reply1 with garbage in the
	// useSecurity / cookie / MTU fields as a challenge. We treat any value
	// other than 0 or 1 in data[24] as "security disabled" and parse the MTU
	// from the next two bytes — this lets the caller treat the packet as a
	// (broken) Reply1 and trigger its OVH workaround instead of failing.
	switch data[24] {
	case 0:
		pk.ServerHasSecurity = false
		pk.MTU = binary.BigEndian.Uint16(data[25:])
	case 1:
		pk.ServerHasSecurity = true
		if len(data) < 31 {
			return io.ErrUnexpectedEOF
		}
		pk.Cookie = binary.BigEndian.Uint32(data[25:29])
		pk.MTU = binary.BigEndian.Uint16(data[29:])
	default:
		// Garbage useSecurity byte. Best-effort decode so the dialer can
		// recognise the packet as a broken Reply1.
		pk.ServerHasSecurity = false
		pk.MTU = binary.BigEndian.Uint16(data[25:])
	}
	return nil
}

func (pk *OpenConnectionReply1) MarshalBinary() (data []byte, err error) {
	offset := 0
	if pk.ServerHasSecurity {
		offset = 4
	}
	b := make([]byte, 28+offset)
	b[0] = IDOpenConnectionReply1
	copy(b[1:], unconnectedMessageSequence[:])
	binary.BigEndian.PutUint64(b[17:], uint64(pk.ServerGUID))
	if pk.ServerHasSecurity {
		b[25] = 1
		binary.BigEndian.PutUint32(b[26:], pk.Cookie)
	}
	binary.BigEndian.PutUint16(b[26+offset:], pk.MTU)
	return b, nil
}

// Package method defines TLS spoofing metadata without socket or adapter dependencies.
package method

type Method int

const (
	MethodWrongSequence Method = iota
	MethodWrongChecksum
	MethodWrongAcknowledgment
	MethodWrongMD5Sig
	MethodWrongTimestamp
)

const (
	MethodNameWrongSequence       = "wrong-sequence"
	MethodNameWrongChecksum       = "wrong-checksum"
	MethodNameWrongAcknowledgment = "wrong-ack"
	MethodNameWrongMD5Sig         = "wrong-md5"
	MethodNameWrongTimestamp      = "wrong-timestamp"
)

func (m Method) String() string {
	switch m {
	case MethodWrongSequence:
		return MethodNameWrongSequence
	case MethodWrongChecksum:
		return MethodNameWrongChecksum
	case MethodWrongAcknowledgment:
		return MethodNameWrongAcknowledgment
	case MethodWrongMD5Sig:
		return MethodNameWrongMD5Sig
	case MethodWrongTimestamp:
		return MethodNameWrongTimestamp
	default:
		return "unknown"
	}
}


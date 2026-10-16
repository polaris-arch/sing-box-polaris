//go:build darwin || linux || windows

package oomprofile

import (
	"encoding/binary"
	"fmt"
	"math"
	"testing"
)

// Independent reader for the pprof fields this collector emits. This verifies
// real encoded samples/locations, not just strings or a nonempty writer buffer.
type decodedProfileField struct {
	tag   uint64
	wire  uint64
	value uint64
	data  []byte
}

func decodeProfileFields(raw []byte) ([]decodedProfileField, error) {
	var fields []decodedProfileField
	for len(raw) > 0 {
		key, n := binary.Uvarint(raw)
		if n <= 0 || key>>3 == 0 {
			return nil, fmt.Errorf("invalid profile field key")
		}
		raw = raw[n:]
		f := decodedProfileField{tag: key >> 3, wire: key & 7}
		switch f.wire {
		case 0:
			value, n := binary.Uvarint(raw)
			if n <= 0 {
				return nil, fmt.Errorf("invalid profile integer")
			}
			f.value = value
			raw = raw[n:]
		case 2:
			length, n := binary.Uvarint(raw)
			if n <= 0 || length > uint64(len(raw)-n) {
				return nil, fmt.Errorf("invalid profile length")
			}
			raw = raw[n:]
			f.data = raw[:int(length)]
			raw = raw[int(length):]
		default:
			return nil, fmt.Errorf("unexpected profile wire type %d", f.wire)
		}
		fields = append(fields, f)
	}
	return fields, nil
}
func decodedProfileIntegers(f decodedProfileField) ([]uint64, error) {
	if f.wire == 0 {
		return []uint64{f.value}, nil
	}
	if f.wire != 2 {
		return nil, fmt.Errorf("unexpected packed profile integer")
	}
	var result []uint64
	for len(f.data) > 0 {
		value, n := binary.Uvarint(f.data)
		if n <= 0 {
			return nil, fmt.Errorf("invalid packed integer")
		}
		result = append(result, value)
		f.data = f.data[n:]
	}
	return result, nil
}
func requireDecodedHeapProfile(t *testing.T, raw []byte) {
	t.Helper()
	fields, err := decodeProfileFields(raw)
	if err != nil {
		t.Fatal(err)
	}
	var strings []string
	var types, samples [][]byte
	locations := map[uint64]bool{}
	for _, f := range fields {
		switch f.tag {
		case 1:
			types = append(types, f.data)
		case 2:
			samples = append(samples, f.data)
		case 4:
			loc, err := decodeProfileFields(f.data)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range loc {
				if f.tag == 1 {
					if f.value == 0 || locations[f.value] {
						t.Fatal("invalid/duplicate location")
					}
					locations[f.value] = true
				}
			}
		case 6:
			strings = append(strings, string(f.data))
		}
	}
	if len(types) != 4 || len(samples) == 0 || len(locations) == 0 {
		t.Fatal("real heap profile lacks sample types/samples/locations")
	}
	for i, want := range []string{"alloc_objects", "alloc_space", "inuse_objects", "inuse_space"} {
		fields, err := decodeProfileFields(types[i])
		if err != nil {
			t.Fatal(err)
		}
		name := ""
		for _, f := range fields {
			if f.tag == 1 {
				if f.value >= uint64(len(strings)) {
					t.Fatal("sample type string index out of bounds")
				}
				name = strings[f.value]
			}
		}
		if name != want {
			t.Fatalf("sample type %q != %q", name, want)
		}
	}
	sawLiveBytes := false
	for _, sample := range samples {
		fields, err := decodeProfileFields(sample)
		if err != nil {
			t.Fatal(err)
		}
		var values []uint64
		for _, f := range fields {
			if f.tag != 1 && f.tag != 2 {
				continue
			}
			numbers, err := decodedProfileIntegers(f)
			if err != nil {
				t.Fatal(err)
			}
			if f.tag == 2 {
				values = append(values, numbers...)
			} else {
				for _, id := range numbers {
					if !locations[id] {
						t.Fatal("sample has dangling location")
					}
				}
			}
		}
		if len(values) != 4 {
			t.Fatal("heap sample omitted counters")
		}
		for _, value := range values {
			if value > math.MaxInt64 {
				t.Fatal("negative or overflowed heap accounting")
			}
		}
		if values[2] > values[0] || values[3] > values[1] {
			t.Fatal("in-use sample exceeds allocations")
		}
		if values[3] > 0 {
			sawLiveBytes = true
		}
	}
	if !sawLiveBytes {
		t.Fatal("actual nonempty heap has no encoded live bytes")
	}
}

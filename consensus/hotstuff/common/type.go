package common

import (
	"encoding/binary"
	"fmt"
)

const (
	// IDBytesLength is the expected length of the ID
	IDBytesLength = 4
)

// ID represents the 4-byte identity of the Hotstuff replica.
type ID [IDBytesLength]byte

func (id ID) Uint32() uint32 {
	return binary.BigEndian.Uint32(id[:])
}

func (id *ID) FromBytes(b []byte) {
	copy(id[:], b)
}

func (id ID) Bytes() []byte {
	return id[:]
}

func (id *ID) SetUint32(i uint32) {
	binary.BigEndian.PutUint32(id[:], i)
}

func (id ID) String() string {
	return fmt.Sprintf("%d", id.Uint32())
}

func (id ID) MarshalText() ([]byte, error) {
	return id[:], nil
}

func (id *ID) UnmarshalText(data []byte) error {
	copy(id[:], data)
	return nil
}

func (id ID) Less(cmp ID) bool {
	for offset := 0; offset < IDBytesLength; offset++ {
		if id[offset] != cmp[offset] {
			return id[offset] < cmp[offset]
		}
	}
	return false
}

// IDSet is a ID slice type for basic sorting
type IDSet []ID

func (set IDSet) Len() int { return len(set) }

func (set IDSet) Swap(i, j int) { set[i], set[j] = set[j], set[i] }

func (set IDSet) Less(i, j int) bool {
	return set[i].Less(set[j])
}

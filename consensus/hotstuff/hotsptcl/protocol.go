package hotstuffprotocol

import (
	"encoding/json"

	"github.com/bigzoro/my_simplechain/common"
)

const (
	// hotsutff events message code
	status uint64 = iota
	propose
	vote
	timeout

	// Maximum cap on the size of a protocol message
	protocolMaxMsgSize = 10 * 1024 * 1024
)

type handshakeData struct {
	Random    []byte
	Signature []byte
}

func (msg *handshakeData) MarshalJSON() ([]byte, error) {
	return json.Marshal(msg)
}

func (msg *handshakeData) UnmarshalJSON(input []byte) error {
	return json.Unmarshal(input, msg)
}

type voteMsg struct {
	View      uint64
	Hash      common.Hash
	Signature []byte
}

func (msg *voteMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(msg)
}

func (msg *voteMsg) UnmarshalJSON(input []byte) error {
	return json.Unmarshal(input, msg)
}

type timeoutMsg struct {
	View uint64
	// Hash *common.Hash
}

func (msg *timeoutMsg) MarshalJSON() ([]byte, error) {
	return json.Marshal(msg)
}

func (msg *timeoutMsg) UnmarshalJSON(input []byte) error {
	return json.Unmarshal(input, msg)
}

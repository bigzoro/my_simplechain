package bls

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/bigzoro/my_simplechain/consensus/hotstuff/common"
	"github.com/bits-and-blooms/bitset"
	bls12381 "github.com/kilic/bls12-381"
)

const (
	BLSfpByteSize = 48
)

var (
	// errBytesLength is returned if the unmarshaled raw bytes do not conform
	// to the specification of a bls12381 scheme.
	errBytesLength = errors.New("invalid raw byte length")

	// errPublicKeyNotFound is returned if the public key corresponding to the
	// signature ID cannot be found in the quorum during signature verification.
	errPublicKeyNotFound = errors.New("public key not found")

	// errInsufficientSigners is returned if a quorum certificate does not
	// contain enough signatures.
	errInsufficientSigners = errors.New("insufficient signers")

	// errFailedVerification is returned if signature verification fails.
	errFailedVerification = errors.New("verification fails")
)

type quorum interface {
	// Count returns the total number of participating replicas.
	Count() int

	// Threshold returns the minimum number of consensus nodes required to achieve
	// aggregation criteria.
	Threshold() int

	// PublicKey returns the public key corresponding to the signature ID.
	PublicKey(common.ID) (*PublicKey, bool)

	// ForEach calls f for each ID in the quorum.
	ForEach(f func(common.ID, *PublicKey))

	// RangeWhile calls f for each ID in the quorum until f returns false
	RangeWhile(f func(common.ID, *PublicKey) bool)
}

// PublicKey is a bls12-381 public key.
type PublicKey struct {
	point *bls12381.PointG1
}

// ToBytes marshals the public key to a byte slice.
func (k PublicKey) ToBytes() []byte {
	return bls12381.NewG1().ToCompressed(k.point)
}

// FromBytes unmarshals the public key from a byte slice.
func (k *PublicKey) FromBytes(b []byte) (err error) {
	k.point, err = bls12381.NewG1().FromCompressed(b)
	if err != nil {
		return fmt.Errorf("bls12: failed to decompress public key: %w", err)
	}
	return nil
}

func (k *PublicKey) UnmarshalJSON(data []byte) error {
	var pbytes []byte
	if err := json.Unmarshal(data, &pbytes); err != nil {
		return err
	}
	return k.FromBytes(pbytes)
}

func (k *PublicKey) MarshalJSON() ([]byte, error) {
	return json.Marshal(k.ToBytes())
}

// PrivateKey is a bls12-381 private key.
type PrivateKey struct {
	sec    *big.Int
	pubkey *PublicKey
}

// SignWithId signs the message and generates a partial signature based on the ID.
func (k *PrivateKey) SignWithId(msg []byte, id common.ID) (*PartialSignature, error) {
	point, err := sign(k.sec, msg)
	if err != nil {
		return nil, err
	}
	return &PartialSignature{pointg2: point, id: id}, nil
}

// Public returns the public key associated with this private key.
func (k *PrivateKey) Public() *PublicKey {
	if k.pubkey == nil {
		k.pubkey = &PublicKey{point: bls12381.NewG1().MulScalarBig(new(bls12381.PointG1), &bls12381.G1One, k.sec)}
	}
	return k.pubkey
}

// ToBytes marshals the private key to a byte slice.
func (k PrivateKey) ToBytes() []byte {
	return k.sec.Bytes()
}

// FromBytes unmarshals the private key from a byte slice.
func (k *PrivateKey) FromBytes(b []byte) {
	k.sec = new(big.Int)
	k.sec.SetBytes(b)
}

// GeneratePrivateKey generates a random private key.
func GeneratePrivateKey() *PrivateKey {
	rd, _ := rand.Int(rand.Reader, curveOrder)
	return &PrivateKey{sec: rd}
}

// AggregateSignature is a bls12-381 aggregate signature. The participants
// field contains the IDs of the replicas that participated in signature
// creation. This allows us to build an aggregated public key to verify the signature.
type AggregateSignature struct {
	pointg2      *bls12381.PointG2
	participants *bitset.BitSet // The ids of the replicas who submitted signatures.
}

// AggregateVerify verifys if the aggregate signature is valid for the message.
func (s *AggregateSignature) Verify(qr quorum, msg []byte) error {
	if s.participants.Count() < uint(qr.Threshold()) {
		return errInsufficientSigners
	}
	pubs := make([]*bls12381.PointG1, 0, s.participants.Count())
	qr.ForEach(func(id common.ID, pk *PublicKey) {
		if s.participants.Test(uint(id.Uint32())) {
			pubs = append(pubs, pk.point)
		}
	})

	if !fastAggregateVerify(msg, s.pointg2, pubs...) {
		return errFailedVerification
	}
	return nil
}

// ToBytes marshals the aggregate signature to a byte slice.
func (s *AggregateSignature) ToBytes() ([]byte, error) {
	id, err := s.participants.MarshalBinary()
	if err != nil {
		return nil, err
	}
	point := bls12381.NewG2().ToCompressed(s.pointg2)
	return append(point, id...), nil
}

// FromBytes unmarshals the aggregate signature from a byte slice.
func (s *AggregateSignature) FromBytes(data []byte) (err error) {
	if len(data) < 2*BLSfpByteSize {
		return errBytesLength
	}
	s.pointg2, err = bls12381.NewG2().FromCompressed(data[:2*BLSfpByteSize])
	if err != nil {
		return err
	}
	s.participants = bitset.New(1)
	return s.participants.UnmarshalBinary(data[2*BLSfpByteSize:])
}

// Clone returns a copy of the aggregate signature.
func (s *AggregateSignature) Clone() *AggregateSignature {
	return &AggregateSignature{
		pointg2:      new(bls12381.PointG2).Set(s.pointg2),
		participants: s.participants.Clone(),
	}
}

// PartialSignature is a bls12-381 partial signature. it contains the ID
// of the replicas that signs this signature.
type PartialSignature struct {
	id      common.ID
	pointg2 *bls12381.PointG2
}

// ID returns the id of signer.
func (s *PartialSignature) ID() common.ID {
	return s.id
}

// Verify verifys if the partial signature is valid for the message.
func (s *PartialSignature) Verify(qr quorum, msg []byte) error {
	pub, ok := qr.PublicKey(s.id)
	if !ok {
		return errPublicKeyNotFound
	}
	if !verify(pub.point, msg, s.pointg2) {
		return errFailedVerification
	}
	return nil
}

// ToBytes marshals the partial signature to a byte slice.
func (s *PartialSignature) ToBytes() ([]byte, error) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, s.id.Uint32())
	return append(bls12381.NewG2().ToCompressed(s.pointg2), buf...), nil
}

// FromBytes unmarshals the partial signature from a byte slice.
func (s *PartialSignature) FromBytes(data []byte) (err error) {
	if len(data) != 2*BLSfpByteSize+4 {
		return errBytesLength
	}

	s.id.SetUint32(binary.LittleEndian.Uint32(data[len(data)-4:]))
	s.pointg2, err = bls12381.NewG2().FromCompressed(data[:2*BLSfpByteSize])
	return
}

type PartialSignatureSet []*PartialSignature

func (set PartialSignatureSet) Len() int { return len(set) }

func (set PartialSignatureSet) Swap(i, j int) { set[i], set[j] = set[j], set[i] }

func (set PartialSignatureSet) Less(i, j int) bool {
	return set[i].ID().Less(set[j].ID())
}

// Combine aggregates some partial signatures into a single aggregate signature.
func Combine(sigs ...*PartialSignature) (*AggregateSignature, error) {
	points := make([]*bls12381.PointG2, 0, len(sigs))
	bits := bitset.New(uint(len(sigs)))
	for _, sig := range sigs {
		points = append(points, sig.pointg2)
		bits.Set(uint(sig.id.Uint32()))
	}
	return &AggregateSignature{pointg2: combine(points...), participants: bits}, nil
}

package hotstuff

import (
	"bytes"
	"encoding/json"
	"errors"
	"sort"

	"github.com/bigzoro/my_simplechain/common"
	bls "github.com/bigzoro/my_simplechain/consensus/hotstuff/bls12-381"
	hots "github.com/bigzoro/my_simplechain/consensus/hotstuff/common"
	"github.com/bigzoro/my_simplechain/ethdb"
	lru "github.com/hashicorp/golang-lru"
	"golang.org/x/crypto/sha3"
)

var (
	// errKnownID is returned when the Legal tries to add a new replica with a duplicate ID.
	errKnownID = errors.New("known ID")

	// errKnownPublicKey is returned when the Legal tries to add a new replica with a duplicate public key.
	errKnownPublicKey = errors.New("known public key")

	// replicaSnapshotKeyPrefix + snapshot hash -> replica information snapshot
	replicaSnapshotKeyPrefix = []byte("hotstuff-")

	// HeadSnapshotKey = []byte("hotstuff-head")

	inmemorySnapshots = 128
)

type rotation interface {
	Leader(uint64, hots.IDSet) hots.ID
}

type basicRotation struct{}

func (br basicRotation) Leader(view uint64, set hots.IDSet) hots.ID {
	if len(set) == 0 {
		return hots.ID{}
	}

	return set[uint64(view)%uint64(len(set))]
}

// snapshot is the state of the replicas at a given point in time.
type snapshot struct {
	// An ordered ID slice ensures that the records of each replica are consistent.
	Idset   hots.IDSet                 `json:"idset"`
	Pubkeys map[hots.ID]*bls.PublicKey `json:"pubkeys"`
}

func NewSnapshot(ids []hots.ID, pks []*bls.PublicKey) *snapshot {
	idset := make(hots.IDSet, 0, len(ids))
	pubkeys := make(map[hots.ID]*bls.PublicKey)

	for i := 0; i < len(ids) && i < len(pks); i++ {
		idset = append(idset, ids[i])
		pubkeys[ids[i]] = pks[i]
	}
	sort.Sort(idset)
	return &snapshot{
		Idset:   ids,
		Pubkeys: pubkeys,
	}
}

// Count returns the total number of participating replicas.
func (s *snapshot) Count() int {
	return len(s.Idset)
}

// Threshold returns the minimum number of consensus nodes required to achieve
// aggregation criteria.
func (s *snapshot) Threshold() int {
	return len(s.Idset) - (len(s.Idset)-1)/3
}

// PublicKey returns the public key corresponding to the signature ID.
func (s *snapshot) PublicKey(id hots.ID) (*bls.PublicKey, bool) {
	key, exist := s.Pubkeys[id]
	return key, exist
}

// ForEach calls f for each ID in the quorum.
func (s *snapshot) ForEach(f func(hots.ID, *bls.PublicKey)) {
	for id, key := range s.Pubkeys {
		f(id, key)
	}
}

// RangeWhile calls f for each ID in the quorum until f returns false
func (s *snapshot) RangeWhile(f func(hots.ID, *bls.PublicKey) bool) {
	for id, key := range s.Pubkeys {
		if !f(id, key) {
			return
		}
	}
}

// Leader returns the ID of leader for a given view
func (s *snapshot) Leader(view uint64, rotate rotation) hots.ID {
	return rotate.Leader(view, s.Idset)
}

func (s *snapshot) set(id hots.ID, pk *bls.PublicKey) {
	if _, ok := s.Pubkeys[id]; !ok {
		s.Idset = append(s.Idset, id)
		sort.Sort(s.Idset)
	}
	s.Pubkeys[id] = pk
}

func (s *snapshot) remove(id hots.ID) {
	if _, ok := s.Pubkeys[id]; ok {
		for i := range s.Idset {
			if bytes.Equal(s.Idset[i].Bytes(), id.Bytes()) {
				s.Idset = append(s.Idset[:i], s.Idset[i+1:]...)
				break
			}
		}
	}
	delete(s.Pubkeys, id)
}

func (s *snapshot) Hash() (hash common.Hash) {
	hasher := sha3.NewLegacyKeccak256()
	for i := range s.Idset {
		hasher.Write(s.Idset[i].Bytes())
		hasher.Write(s.Pubkeys[s.Idset[i]].ToBytes())
	}
	hasher.Sum(hash[:0])
	return
}

func (s *snapshot) clone() *snapshot {
	idset := make(hots.IDSet, len(s.Idset))
	copy(idset, s.Idset)

	pubkeys := make(map[hots.ID]*bls.PublicKey)
	for id, pk := range s.Pubkeys {
		pubkeys[id] = pk
	}
	return &snapshot{
		Idset:   idset,
		Pubkeys: pubkeys,
	}
}

func (s *snapshot) Store(db ethdb.Database) error {
	blob, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return db.Put(append(replicaSnapshotKeyPrefix, s.Hash().Bytes()...), blob)
}

func loadSnapshot(db ethdb.Database, hash common.Hash) (*snapshot, error) {
	raw, err := db.Get(append(replicaSnapshotKeyPrefix, hash.Bytes()...))
	if err != nil {
		return nil, err
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		return nil, err
	}
	return &snap, nil
}

// Legal tracks the valid Hotstuff relicas and records their public keys and IDs
type Legal struct {
	rot rotation

	recent *lru.ARCCache

	db ethdb.Database
}

func NewLegal(db ethdb.Database) *Legal {
	recent, _ := lru.NewARC(inmemorySnapshots)
	return &Legal{
		db:     db,
		rot:    basicRotation{},
		recent: recent,
	}
}

func (lg *Legal) snapshot(hash common.Hash) (s *snapshot, err error) {
	if val, ok := lg.recent.Get(hash); ok {
		return val.(*snapshot), nil
	}

	s, err = loadSnapshot(lg.db, hash)
	if err != nil {
		return nil, err
	}
	lg.recent.Add(hash, s)
	return s, nil
}

func (lg *Legal) store(snap *snapshot) error {
	if err := snap.Store(lg.db); err != nil {
		return err
	}
	lg.recent.Add(snap.Hash(), snap)
	return nil
}

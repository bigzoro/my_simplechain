// Copyright 2014 The go-simplechain Authors
// This file is part of the go-simplechain library.
//
// The go-simplechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-simplechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-simplechain library. If not, see <http://www.gnu.org/licenses/>.

package types

import (
	"bytes"
	"github.com/exascience/pargo/parallel"
	"golang.org/x/crypto/sha3"
	"runtime"
	"sort"

	parallelSort "github.com/exascience/pargo/sort"
	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/rlp"
	"github.com/simplechain-org/go-simplechain/trie"
)

type DerivableList interface {
	Len() int
	GetRlp(i int) []byte
}

type BytesPair struct {
	//Key   []byte `gencodec:"required"`
	Key   uint32 `gencodec:"required"`
	Value []byte `gencodec:"required"`
}

func DeriveLegacySha(list DerivableList) common.Hash {
	keybuf := new(bytes.Buffer)
	trie := new(trie.Trie)
	for i := 0; i < list.Len(); i++ {
		keybuf.Reset()
		rlp.Encode(keybuf, uint(i))
		trie.Update(keybuf.Bytes(), list.GetRlp(i))
	}
	return trie.Hash()
}

func DeriveListShaParallel(list DerivableList) (h common.Hash) {
	l := list.Len()
	ordered := make([]BytesPair, l)

	parallel.Range(0, l, runtime.NumCPU(), func(low, high int) {
		for i := low; i < high; i++ {
			ordered[i] = BytesPair{uint32(i), list.GetRlp(i)}
			//keybuf := new(bytes.Buffer)
			//rlp.Encode(keybuf, uint(i))
			//ordered[i] = BytesPair{keybuf.Bytes(), list.GetRlp(i)}
		}
	})

	parallelSort.Sort(parallelOrderedSorter(ordered))

	hw := sha3.NewLegacyKeccak256()
	rlp.Encode(hw, ordered)
	hw.Sum(h[:0])
	return h
}

type parallelOrderedSorter []BytesPair

func (s parallelOrderedSorter) Len() int {
	return len(s)
}
func (s parallelOrderedSorter) Less(i, j int) bool {
	return s[i].Key < s[j].Key
	//return bytes.Compare(s[i].Key, s[j].Key) < 0
}
func (s parallelOrderedSorter) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s parallelOrderedSorter) SequentialSort(i, j int) {
	sort.Slice(s, func(i, j int) bool {
		return s[i].Key < s[j].Key
		//return bytes.Compare(s[i].Key, s[j].Key) < 0
	})
}

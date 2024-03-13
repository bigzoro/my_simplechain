package raft

import "testing"

func TestFile(t *testing.T) {
	_, err := ReadGenRaftConfigJson([]byte("111111"), "D:/")
	if err != nil {
		panic(err)
	}
}

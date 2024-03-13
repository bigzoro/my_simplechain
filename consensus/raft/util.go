package raft

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	uuid "github.com/satori/go.uuid"
	"github.com/simplechain-org/go-simplechain/crypto"
	"github.com/simplechain-org/go-simplechain/log"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

type raftConfig struct {
	RaftId uint16 `json:"raftId"`
}

const raftFile = "raftConfig.json"

// TODO: this is just copied over from cmd/utils/cmd.go. dedupe
// Fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func Fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

func GetRaftIdFromEnodeId(enode []byte) uint16 {
	enodeHash := crypto.Keccak256(enode)
	return binary.BigEndian.Uint16(enodeHash[30:])
}

func GetRandomRaftIdFromEnodeId(enode []byte) (uint16, error) {
	packageUUID := uuid.NewV4()
	enode = append(enode, []byte(packageUUID.String())...)
	return GetRaftIdFromEnodeId(enode), nil
}

func ReadGenRaftConfigJson(enode []byte, path string) (uint16, error) {
	var rc raftConfig
	fileBytes, err := ioutil.ReadFile(filepath.Join(path, raftFile))
	if err != nil {
		raftId, err := GetRandomRaftIdFromEnodeId(enode)
		if err != nil {
			log.Error(err.Error())
			return 0, err
		}
		rc.RaftId = raftId
	} else {
		err = json.Unmarshal(fileBytes, &rc)
		if err != nil {
			log.Error(err.Error())
			return 0, err
		}
	}
	data, err := json.Marshal(rc)
	if err != nil {
		log.Error("mashral raft config failed")
		return 0, err
	}
	return rc.RaftId, ioutil.WriteFile(filepath.Join(path, raftFile), data, 0700)
}

func GetRaftConfigJson(path string) (uint16, error) {
	fileBytes, err := ioutil.ReadFile(filepath.Join(path, raftFile))
	if err != nil {
		return 0, err
	}
	var rc = raftConfig{}
	err = json.Unmarshal(fileBytes, &rc)
	if err != nil {
		return 0, err
	}
	return rc.RaftId, nil
}

func GenUpdateRaftConfigJson(enode []byte, path string) (uint16, error) {
	var rc = raftConfig{}
	raftId, err := GetRandomRaftIdFromEnodeId(enode)
	if err != nil {
		log.Error(err.Error())
		return 0, err
	}
	rc.RaftId = raftId
	data, err := json.Marshal(rc)
	if err != nil {
		log.Error("mashral raft config failed")
		return 0, err
	}
	return raftId, ioutil.WriteFile(filepath.Join(path, raftFile), data, 0700)
}

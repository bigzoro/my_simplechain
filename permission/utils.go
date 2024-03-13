package permission

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/simplechain-org/go-simplechain/accounts"
	"github.com/simplechain-org/go-simplechain/accounts/keystore"
	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/ethdb"
)

func splitENode(eNode string) (string, string, string, error) {
	eNodeIdAndHost := strings.Split(eNode, "@")
	if len(eNodeIdAndHost) != 2 {
		return "", "", "", errors.New("eNode format error")
	}
	eNodeId := eNodeIdAndHost[0]
	hostAndPort := strings.Split(eNodeIdAndHost[1], ":")
	if len(hostAndPort) != 2 {
		return "", "", "", errors.New("eNode format error")
	}
	ip := hostAndPort[0]
	port := hostAndPort[1]
	//may be have ?discport=0
	temp := strings.Split(port, "?")
	port = temp[0]
	return eNodeId, ip, port, nil
}

func splitPort(eNode string) (string, uint16, error) {
	tmp := strings.Split(eNode, "&raftid=")
	if len(tmp) != 2 {
		return "", 0, errors.New("enode format error")
	}
	tmp2, err := strconv.Atoi(tmp[1])
	if err != nil {
		return "", 0, err
	}
	return tmp[0], uint16(tmp2), nil
}

func storeContractAddress(key []byte, value common.Address, db ethdb.Database) error {
	if value == (common.Address{}) {
		return errors.New("address is empty,please take care of it")
	}
	if db == nil {
		return errors.New("ethDB is nil,please take care of it")
	}
	err := db.Put(key, value.Bytes())
	if err != nil {
		return err
	}
	return nil
}

func loadContractAddress(key []byte, db ethdb.Database) (common.Address, error) {
	if db == nil {
		return common.Address{}, errors.New("db is nil,please take care of it")
	}
	has, err := db.Has(key)
	if err != nil {
		return common.Address{}, err
	}
	if !has {
		//还没有存在，我们直接返回nil,调用端需自行判断不为common.Address{}以后，再使用
		return common.Address{}, nil
	}
	ret, err := db.Get(key)
	if err != nil {
		return common.Address{}, err
	}
	if ret == nil {
		return common.Address{}, fmt.Errorf("can not get contract address")
	}
	addr := common.BytesToAddress(ret)
	return addr, nil
}

// fetchKeystore retrives the encrypted keystore from the account manager.
func fetchKeystore(am *accounts.Manager, account accounts.Account) (*keystore.KeyStore, error) {
	index, err := am.FindAccIndex(account)
	if err != nil {
		return nil, err
	}
	return am.Backends(keystore.KeyStoreType)[index].(*keystore.KeyStore), nil
}

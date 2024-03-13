package db

import (
	"encoding/binary"
	"github.com/simplechain-org/go-simplechain/core/rawdb"
	"github.com/simplechain-org/go-simplechain/core/state"
	ethdb "github.com/simplechain-org/go-simplechain/ethdb/leveldb"
	"github.com/syndtr/goleveldb/leveldb"
	"testing"

	"github.com/simplechain-org/go-simplechain/common"
)

func TestInsetIdHash(t *testing.T) {
	hashDb, err := NewLDBDatabase("./IdHash", 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	TxId := common.BytesToHash(common.FromHex("0xd962b109b0bfdef7d6568cff8e6fe24d55e80d5749f6d80ddea66c0647dbb03a"))
	hashData := common.FromHex("0xe267591b78ab7ffc97fab9e9ae55ae2db067225dde4e989b7ec071b125ca6b94")

	if err := hashDb.InsertHash(hashData, TxId); err != nil {
		t.Fatal("InsertHash failed: ", err)
	}

	re, err := hashDb.GetHashId(hashData)
	if err != nil {
		t.Fatal(err)
	}
	if re != TxId {
		t.Fatal("the hash not equal ")
	}

	//fmt.Println(re.String(),err)
}
func encodeBlockNumber(number uint64) []byte {
	enc := make([]byte, 8)
	binary.BigEndian.PutUint64(enc, number)
	return enc
}
func TestModifyBlock(t *testing.T) {
	db, err := leveldb.OpenFile("/home/lixuecheng/goProject/src/github.com/simplechainleague/testtpsdata/test-node-1/sipe/chaindata", nil)
	if err != nil {
		t.Fatal("openFile" + err.Error())
	}
	defer db.Close()
	headBlockKey := []byte("LastBlock")
	blockBodyPrefix := []byte("b")
	hash := common.BytesToHash(common.FromHex("0x1e40eae5b5d314e9463889336834b0cc700e4f6a30ad91aaa1ad10a012de2df6"))
	data, err := db.Get(headBlockKey[:], nil)
	if err != nil {
		t.Fatal("read block failed " + err.Error())
	}
	t.Log("get block", data)

	key := append(append(blockBodyPrefix, encodeBlockNumber(5)...), hash.Bytes()...)
	data1, err := db.Get(key[:], nil)
	if err != nil {
		t.Fatal("get block body failed " + err.Error())
	}
	t.Log("get block body", data1)

	configPrefix := append([]byte("ethereum-config-"))
	data2, err := db.Get(configPrefix[:], nil)
	if err != nil {
		t.Fatal("get block body failed " + err.Error())
	}
	t.Log("get block body", data2)
}

func TestModifyState(t *testing.T) {
	//db, err := leveldb.OpenFile("/home/lixuecheng/goProject/src/github.com/simplechainleague/testtpsdata/test-node-1/sipe/chaindata", nil)
	//if err != nil {
	//	t.Fatal("openFile" + err.Error())
	//}
	//defer db.Close()
	//headBlockKey := []byte("LastBlock")
	//data, err := db.Get(headBlockKey[:], nil)
	//if err != nil {
	//	t.Fatal("read block failed " + err.Error())
	//}
	//t.Log("get block", data)

	root := common.BytesToHash(common.FromHex("0x1411d96a8527236473e10d150bac66e5ce25c5eda58f5fd4836606befc436a3f"))
	//key := append([]byte("secure-key-"), root.Bytes()...)
	t.Log("get key ", root)
	//data1, err := db.Get(root[:], nil)
	//if err != nil {
	//	t.Fatal("get block failed " + err.Error())
	//}
	//t.Log("get state ", data1)
	db, err := ethdb.New("/home/lixuecheng/goProject/src/github.com/simplechainleague/testtpsdata/test-node-1/sipe/chaindata", 0, 0, "")
	if err != nil {
		t.Fatal("get ethDB failed " + err.Error())
	}
	ethDB := rawdb.NewDatabase(db)
	statedb, err := state.New(root, state.NewDatabase(ethDB))
	if err != nil {
		t.Fatal("get statedb failed " + err.Error())
	}
	account := common.HexToAddress("0x701b014b225b2127299eea5d3dcd2071f3321004")
	//statedb.SetBalance(account, big.NewInt(0))
	t.Log("balance ", statedb.GetBalance(account))

	it := db.NewIteratorWithPrefix(root.Bytes())
	for {
		if !it.Next() {
			break
		}
		t.Log("key ", common.Bytes2Hex(it.Key()), "value ", common.Bytes2Hex(it.Value()))
	}
	err = db.Put(root.Bytes(), nil)
	if err != nil {
		t.Fatal("delete failed " + err.Error())
	}
	db.Close()
	//TxId := common.BytesToHash(common.FromHex("0x345e53a66830c2e67757b13eda9cb64573ead9c8a61e5f29ab539cc99b0b7aed"))
	//data2, err := db.Get(TxId[:], nil)
	//if err != nil {
	//	t.Fatal("get block failed " + err.Error())
	//}
	//t.Log("get block", "block", data2)
}

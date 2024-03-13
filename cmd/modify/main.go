package main

import (
	"flag"
	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/core/rawdb"
	"github.com/bigzoro/my_simplechain/core/state"
	ethdb "github.com/bigzoro/my_simplechain/ethdb/leveldb"
	"log"
)

func main() {

	path := flag.String("path", "", "leveldb file")
	stateRoot := flag.String("root", "", "state root")
	acc := flag.String("acc", "", "account")
	flag.Parse()
	log.Printf("params: %v %v %v", *path, *stateRoot, *acc)
	root := common.BytesToHash(common.FromHex(*stateRoot))

	db, err := ethdb.New(*path, 0, 0, "")
	if err != nil {
		log.Fatal("get ethDB failed " + err.Error())
	}
	ethDB := rawdb.NewDatabase(db)
	statedb, err := state.New(root, state.NewDatabase(ethDB))
	if err != nil {
		log.Fatal("get statedb failed " + err.Error())
	}
	account := common.HexToAddress(*acc)
	log.Printf("balance: %v\n ", statedb.GetBalance(account))

	rs, err := db.Get(root.Bytes())
	if err != nil {
		log.Fatal("get state root failed " + err.Error())
	}
	log.Printf("get state root: %v", rs)
	//it := db.NewIteratorWithPrefix(root.Bytes())
	//for {
	//	if !it.Next() {
	//		break
	//	}
	//	t.Log("key ", common.Bytes2Hex(it.Key()), "value ", common.Bytes2Hex(it.Value()))
	//}
	err = db.Delete(root.Bytes())
	if err != nil {
		log.Fatal("delete failed " + err.Error())
	}
	defer db.Close()
	rs, err = db.Get(root.Bytes())
	if err != nil {
		log.Fatal("after modify, get state root failed " + err.Error())
	}
	log.Printf("after modify, get state root: %v", rs)
	log.Println("dummy transaction exit")
}

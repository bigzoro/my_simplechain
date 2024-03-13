package main

import (
	"context"
	"github.com/simplechain-org/go-simplechain/cmd/dummytx/config"
	"log"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 4 {
		log.Printf("Usage: dummyTx config.json 500 1\n")
		os.Exit(1)
	}
	txNums, err := strconv.ParseInt(os.Args[2], 10, 64)
	if err != nil {
		log.Printf("the second para is not number\n")
		os.Exit(1)
	}
	num, err := strconv.ParseInt(os.Args[3], 10, 64)
	if err != nil {
		log.Printf("the third para is not number\n")
		os.Exit(1)
	}
	if num < 0 {
		log.Printf("the third para is less than 0\n")
		os.Exit(1)
	}
	switch num {
	case 0:
		for {
			ctx, cancel := context.WithCancel(context.Background())
			conf := config.LoadConfig(os.Args[1])
			s := newSender(ctx, conf, txNums)
			s.connect() // 连接上某sipe节点
			s.claimFunds()
			if conf.Monitor {
				log.Println("start monitor txs in blockChain")
				go s.calcTotalCount(ctx)
			}
			go s.dummyTx()
			for i := 0; i < 1; i++ {
				<-s.signal
			}
			close(s.signal)
			s.client.Close()
			cancel()
			log.Printf("txsCount=%v", s.txsCount)
		}
	default:
		for j := 0; j < int(num); j++ {
			ctx, cancel := context.WithCancel(context.Background())
			conf := config.LoadConfig(os.Args[1])
			s := newSender(ctx, conf, txNums)
			s.connect() // 连接上某sipe节点
			s.claimFunds()
			if conf.Monitor {
				log.Println("start monitor txs in blockChain")
				go s.calcTotalCount(ctx)
			}
			go s.dummyTx()
			for i := 0; i < 1; i++ {
				<-s.signal
			}
			close(s.signal)
			s.client.Close()
			cancel()
			log.Printf("txsCount=%v", s.txsCount)
		}
	}
	log.Println("dummy transaction exit")
}

package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	common2 "github.com/simplechain-org/go-simplechain/cmd/dummytx/common"
	"github.com/simplechain-org/go-simplechain/cmd/dummytx/config"
	"log"
	"math/big"
	"strconv"
	"time"

	"github.com/simplechain-org/go-simplechain/common"
	"github.com/simplechain-org/go-simplechain/core/types"
	"github.com/simplechain-org/go-simplechain/crypto"
	"github.com/simplechain-org/go-simplechain/ethclient"
)

const (
	warnPrefix = "\x1b[93mwarn:\x1b[0m"
	errPrefix  = "\x1b[91merror:\x1b[0m"
)

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

type Sender struct {
	url           string
	keyFile       string
	certFile      string
	rootCAFile    []string
	ctx           context.Context
	client        *ethclient.Client
	senders       []common.Address
	pks           []*ecdsa.PrivateKey
	receiver      common.Address
	gasPrice      *big.Int
	gasLimit      *big.Int
	dummyInternal int64
	chainID       string
	txsCount      int64
	signal        chan bool
	firstNonce    uint64
}

func newSender(ctx context.Context, config *config.Config, txsCount int64) *Sender {
	var s = &Sender{
		url:           config.SipeAddr,
		keyFile:       config.PrivateKey,
		certFile:      config.Cert,
		rootCAFile:    config.CACerts,
		ctx:           ctx,
		receiver:      common.HexToAddress(config.Receiver),
		gasPrice:      big.NewInt(config.GasPrice),
		gasLimit:      big.NewInt(config.GasPriceLimit),
		dummyInternal: config.DummyInternal,
		txsCount:      txsCount,
		chainID:       config.ChainId,
		signal:        make(chan bool, 1),
	}

	for i, pk := range config.SenderPrivateKey {
		key, err := common2.GetKey(pk, config.SenderPrivateKeyPassword[i])
		if err != nil {
			log.Fatalf(errPrefix+" get private key file: %v", err)
		}
		privateKey := key.PrivateKey
		s.pks = append(s.pks, privateKey)
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatalf(errPrefix + " cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		}
		fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
		log.Printf("sender:%d %s\n", i, fromAddress.String())

		s.senders = append(s.senders, fromAddress)
	}
	return s
}

func (s *Sender) connect() {
	client, err := ethclient.Dial(s.url, s.certFile, s.keyFile, s.rootCAFile)
	if err != nil {
		log.Fatalf(errPrefix+" connect %s: %v", s.url, err)
	}

	s.client = client
}

func (s *Sender) dummyTx() {
	gasPrice, err := s.client.SuggestGasPrice(s.ctx)
	if err != nil {
		log.Fatalf(errPrefix+" get gas price: %v", err)
	}
	s.gasPrice = gasPrice

	for i, sender := range s.senders {
		go s.loopSendTxsByNum(i, sender)
	}
}

func (s *Sender) claimFunds() {
	value := new(big.Int).Mul(big.NewInt(10000), big.NewInt(1)) // in wei (10000 eth)
	for i, sender := range s.senders {
		nonce, err := s.client.PendingNonceAt(s.ctx, sender)
		if err != nil {
			log.Fatalf(errPrefix+" get new nonce: %v", err)
		}
		tx := types.NewTransaction(nonce, sender, value, s.gasLimit.Uint64(),  s.gasPrice, nil)
		//Remove signature for POA test
		chainID, err := strconv.ParseInt(s.chainID, 10, 64)
		if err != nil {
			log.Fatalf(errPrefix+"chainid transfer failed %v", err)
		}
		signedTx, err := types.SignTx(tx, types.NewEIP155Signer(new(big.Int).SetInt64(chainID)), s.pks[i])
		if err != nil {
			log.Fatalf(errPrefix+" sign tx in claimFunds: %v", err)
		}
		err = s.client.SendTransaction(s.ctx, signedTx)
		if err != nil {
			log.Fatalf(errPrefix+" sign tx in claimFunds: %v", err)
		}
		nonce++
	}
	log.Printf("waiting %v seconds for claim funds txs finalize to block...\n", s.dummyInternal)
	time.Sleep(time.Duration(s.dummyInternal) * time.Second)
}

func (s *Sender) loopSendTxsByNum(index int, fromAddress common.Address) {
	nonce, err := s.client.PendingNonceAt(s.ctx, fromAddress)
	if err != nil {
		log.Fatalf(errPrefix+" get new nonce: %v", err)
	}
	s.firstNonce = nonce
	for i := 0; i < int(s.txsCount); i++ {
		go s.sendTx(nonce+uint64(i), index, fromAddress)
	}
}

func (s *Sender) sendTx(nonce uint64, index int, fromAddress common.Address) {
	var (
		data [20 + 64]byte
	)
	copy(data[:], fromAddress.Bytes())
	_, _ = rand.Read(data[20:]) //hash
	s.sendDummyTx(nonce, data[:], fromAddress, index)
}

func (s *Sender) sendDummyTx(nonce uint64, data []byte, fromAddress common.Address, index int) {
	tx := types.NewTransaction(nonce, fromAddress, big.NewInt(0), s.gasLimit.Uint64(),  s.gasPrice, data)
	//Remove signature for POA test
	chainID, err := strconv.ParseInt(s.chainID, 10, 64)
	if err != nil {
		log.Fatalf(errPrefix+"chainid transfer failed %v", err)
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(new(big.Int).SetInt64(chainID)), s.pks[index])
	if err != nil {
		log.Fatalf(errPrefix+"sign tx: %v", err)
	}
	err = s.client.SendTransaction(s.ctx, signedTx)
	if err != nil {
		log.Printf(warnPrefix+" send tx: %v", err)
	}
}

func (s *Sender) calcTotalCount(ctx context.Context) {
	heads := make(chan *types.Header, 1)
	sub, err := s.client.SubscribeNewHead(context.Background(), heads)
	if err != nil {
		log.Fatalf(errPrefix+"Failed to subscribe to head events %v", err)
	}
	defer sub.Unsubscribe()

	var (
		txsCount           uint
		finalCount         uint64
		start              = time.Now()
		calcTotalCountExit = func(txsCount uint64, seconds float64) {
			log.Printf("total finalize %v txs in %v seconds, %v txs/s", txsCount, seconds, float64(txsCount)/seconds)
		}
	)
	for {
		select {
		case <-ctx.Done():
			calcTotalCountExit(finalCount, time.Since(start).Seconds())
			s.signal <- true
			return
		case head := <-heads:
			txsCount, err = s.client.TransactionCount(ctx, head.Hash())
			if err != nil {
				log.Printf(warnPrefix+"get txCount of block %v: %v", head.Hash(), err)
			}

			log.Printf("Time %8.2fs\tblock Number %6d\ttxCount %6d", time.Since(start).Seconds(), head.Number.Uint64(), txsCount)

			finalCount += uint64(txsCount)
			nonce, err := s.client.NonceAt(s.ctx, s.senders[0], big.NewInt(int64(head.Number.Uint64())))
			if err != nil {
				continue
			}
			if s.firstNonce+uint64(s.txsCount) == nonce {
				calcTotalCountExit(finalCount, time.Since(start).Seconds())
				s.signal <- true
				return
			}
		default:
			//do nothing
		}
	}
}

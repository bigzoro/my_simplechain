//+build sub,old

package main

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"flag"
	"log"
	"math/big"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
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

var (
	txsCount = int64(0)
	signer   types.Signer
	stopCh   = make(chan struct{})

	errTxPoolIsFull = errors.New("txpool is full")
	errInvalidLimit = errors.New("overflow blockLimit")
)

var senderKeys = []string{
	"5aedb85503128685e4f92b0cc95e9e1185db99339f9b85125c1e2ddc0f7c4c48",
	"41a6df5663e5f674baaea1a021cdee1751ca28777e352ed0467fff420017978b",
	"868d8f8b3d50e2a3ebfd5a08b16d84ee015db519d662bb0e5878388f0c15a6e3",
	"9259787a40ec58154e7e04ae324b965cb4f199b1ef09708319d50ad36fc1cbeb",
	"a42531bd0a7c1df628ab141f3be6086146ed01f74628a467f9f926b3625e17a0",
	"2d396fd91b652c687bc6796932a39f190cf7b4aab26e079f8f28baba9939847e",
	"35daed192142a1b608b60390036e7d3ad11ec6bc2d09182f3192f70ed54d4f2f",
	"6ce1ddaaa7cd15232fd17838ab65b7beb8b6ad8e43be7d61548535b40a2a89b0",
}

//var receivers []common.Address
//var senders []*ecdsa.PrivateKey

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
}

const SENDS = 1000000

func initNonce(seed uint64, count int) []uint64 {
	ret := make([]uint64, count)

	bigseed := seed * 1e10
	for i := 0; i < count; i++ {
		ret[i] = bigseed
		bigseed++
	}
	return ret
}

var (
	chainId   *uint64
	tps       *int
	toAddress common.Address
	random    *bool
	checkTx   *bool
)

func main() {
	url := flag.String("url", "ws://127.0.0.1:8546", "websocket url")
	chainId = flag.Uint64("chainid", 1, "chainId")
	tps = flag.Int("tps", -1, "send tps limit, negative is limitless")

	sendTx := flag.Bool("sendtx", false, "enable only send tx")
	senderCount := flag.Int("threads", 4, "the number of sender")
	senderKey := flag.String("sendkey", senderKeys[0], "sender private key")
	callcode := flag.Bool("callcode", false, "enable call contract code")
	to := flag.String("to", "", "tx reception")

	seed := flag.Uint64("seed", 1, "hash seed")
	random = flag.Bool("rand", false, "random signer and receiver tx")
	checkTx = flag.Bool("check", false, "whether check transaction state")

	flag.Parse()

	var cancels []context.CancelFunc

	signer = types.NewEIP155Signer(new(big.Int).SetUint64(*chainId))

	if *callcode {

	}

	if *to != "" {
		toAddress = common.HexToAddress(*to)
	}

	if *sendTx {
		log.Printf("start send tx: %d accounts", *senderCount)

		privateKey, err := crypto.HexToECDSA(*senderKey)
		if err != nil {
			log.Fatalf(errPrefix+" parse private key: %v", err)
		}
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			log.Fatalf(errPrefix + " cannot assert type: publicKey is not of type *ecdsa.PublicKey")
		}
		fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)

		nonces := initNonce(*seed, SENDS*(*senderCount))
		for i := 0; i < *senderCount; i++ {
			client, err := ethclient.Dial(*url, "", "", nil)
			if err != nil {
				log.Fatalf(errPrefix+" connect %s: %v", *url, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancels = append(cancels, cancel)

			go throughputs(ctx, client, i, privateKey, fromAddress, nonces[i*SENDS:(i+1)*SENDS])
		}
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	<-interrupt
	close(stopCh)

	for _, cancel := range cancels {
		cancel()
	}

	log.Printf("Check transation results, success: %d, failed:%d, timeout:%d", successTx, failedTx, timeoutTx)

}

func getBlockLimit(ctx context.Context, client *ethclient.Client, last uint64) uint64 {
	block, err := client.BlockByNumber(ctx, nil)
	if err != nil {
		log.Printf(warnPrefix+"Failed to getBlockLimit: %v", err)
		return last + 100
	}
	return block.NumberU64() + 100
}

var big1 = big.NewInt(1)
var big1e20, _ = new(big.Int).SetString("100000000000000000000", 10)

func throughputs(ctx context.Context, client *ethclient.Client, index int, privateKey *ecdsa.PrivateKey, fromAddress common.Address, nonces []uint64) {
	gasLimit := uint64(21000 + (20+64)*68) // in units
	gasPrice, err := client.SuggestGasPrice(ctx)
	if err != nil {
		log.Fatalf(errPrefix+" get gas price: %v", err)
	}
	var (
		data       [20 + 64]byte
		blockLimit = getBlockLimit(ctx, client, 0)
		meterCount = 0
		i          int
		receivers  []common.Address
		senders    []*ecdsa.PrivateKey
	)

	copy(data[:], fromAddress.Bytes())

	if *random {
		receivers = make([]common.Address, *tps)
		senders = make([]*ecdsa.PrivateKey, *tps)
		for i := 0; i < *tps; i++ {
			pks, _ := crypto.GenerateKey()
			pkr, _ := crypto.GenerateKey()
			senders[i] = pks
			receivers[i] = crypto.PubkeyToAddress(pkr.PublicKey)
		}

		sender, _ := crypto.HexToECDSA(senderKeys[0])
		blockLimit := getBlockLimit(ctx, client, 0)
		nonce := nonces[0]

		for i, s := range senders {
			sendTransaction(ctx, sender, nonce+uint64(i), blockLimit, crypto.PubkeyToAddress(s.PublicKey), big1e20, uint64(21000+(20+64)*68), gasPrice, nil, client)
		}
	}

	start := time.Now()
	timer := time.NewTimer(0)
	<-timer.C
	timer.Reset(10 * time.Minute)

	//tpsInterval := 10 * time.Minute
	//if *tps > 0 {
	//	tpsInterval = time.Second
	//}
	tpsTicker := time.NewTicker(time.Second)
	defer tpsTicker.Stop()

	noncesLen := len(nonces)
	sendersLen := len(senders)

	for {
		if i >= noncesLen {
			break
		}

		select {
		case <-stopCh:
			return
		case <-ctx.Done():
			seconds := time.Since(start).Seconds()
			log.Printf("throughputs:%v return (total %v in %v s, %v txs/s)", index, meterCount, seconds, float64(meterCount)/seconds)
			atomic.AddInt64(&txsCount, int64(meterCount))
			return

		//case <-time.After(10 * time.Second):
		//	blockLimit += 10

		case <-tpsTicker.C:
			if *tps <= 0 {
				*tps = len(nonces)
			}

			var update bool
			for j := 0; j < *tps && i < noncesLen; j++ {
				nonce := nonces[i]

				copy(data[20:], new(big.Int).SetUint64(nonce).Bytes())
				//parallel.Put(func() error {
				//	sendTransaction(ctx, signer, privateKey, nonce, blockLimit, toAddress, big1, gasLimit, gasPrice, data[:], client)
				//	return nil
				//})
				if *random {
					turn := j % sendersLen
					privateKey = senders[turn]
					toAddress = receivers[turn]
				}

				hash, err := sendTransaction(ctx, privateKey, nonce, blockLimit, toAddress, big1, gasLimit, gasPrice, data[:], client)

				if err == errTxPoolIsFull {
					time.Sleep(time.Second * 5) // waiting block
					continue

				}
				if err == errInvalidLimit {
					update = true
					break
				}

				if *checkTx && hash != (common.Hash{}) {
					checkTransaction(ctx, hash, client)
				}

				i++
				meterCount++

				//switch {
				//if i%10000 == 0 {
				//	handle pre-prepare = getBlockLimit(ctx, client, blockLimit)
				//}

			}

			if update {
				blockLimit = getBlockLimit(ctx, client, blockLimit)
			} else {
				blockLimit++
			}
			//blockLimit = getBlockLimit(ctx, client, blockLimit)
			//atomic.AddInt64(&txsCount, int64(meterCount))
			//// statistics throughputs
			//if *tps > 0 && meterCount > *tps {
			//	// sleep to cut down throughputs if higher than limit tps
			//	time.Sleep(time.Duration(meterCount / *tps) * time.Second)
			//}
			//
			//meterCount = 0
		}
	}
}

func sendTransaction(ctx context.Context, key *ecdsa.PrivateKey, nonce, limit uint64, toAddress common.Address,
	value *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, client *ethclient.Client) (common.Hash, error) {

	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)
	tx.SetBlockLimit(limit)

	signature, err := crypto.Sign(signer.Hash(tx).Bytes(), key)
	if err != nil {
		log.Printf(warnPrefix+" send tx[hash:%s, nonce:%d]: %v", tx.Hash().String(), tx.Nonce(), err)
		return common.Hash{}, err
	}
	signed, err := tx.WithSignature(signer, signature)
	if err != nil {
		log.Printf(warnPrefix+" send tx[hash:%s, nonce:%d]: %v", tx.Hash().String(), tx.Nonce(), err)
		return common.Hash{}, err
	}
	err = client.SendTransaction(ctx, signed)
	switch err {
	case nil:
		//recordsMu.Lock()
		//records = append(records, signed.Hash())
		//recordsMu.Unlock()
	case context.Canceled:
		return common.Hash{}, nil
	default:
		log.Printf(warnPrefix+" send tx[hash:%s, nonce:%d]: %v", tx.Hash().String(), tx.Nonce(), err)
		if strings.Contains(err.Error(), "txpool is full") {
			return common.Hash{}, errTxPoolIsFull
		}
		if strings.Contains(err.Error(), "overflow blockLimit") || strings.Contains(err.Error(), "expired transaction") {
			return common.Hash{}, errInvalidLimit
		}
		return common.Hash{}, err
	}

	return signed.Hash(), nil
}

var (
	timeoutTx uint32
	successTx uint32
	failedTx  uint32
)

func checkTransaction(ctx context.Context, hash common.Hash, client *ethclient.Client) {
	go func() {
		for {
			select {
			case <-time.After(time.Second):
				r, err := client.TransactionReceipt(ctx, hash)
				if err == nil {
					if r.Status == 0 {
						atomic.AddUint32(&failedTx, 1)
						log.Printf(warnPrefix+"tx failed: hash: %s", hash.String())
					} else {
						atomic.AddUint32(&successTx, 1)
					}
					return
				}
				if err == context.Canceled {
					return
				}

			case <-time.After(time.Minute):
				atomic.AddUint32(&timeoutTx, 1)
				log.Printf(warnPrefix+"tx timeout: hash: %s", hash.String())
				return
			}
		}
	}()
}
module github.com/bigzoro/my_simplechain

go 1.13

replace (
	github.com/asdine/storm/v3 => github.com/simplechain-org/storm/v3 v3.2.1-0.20200521045524-c61eb1b00dec
	github.com/coreos/etcd => github.com/simplechain-org/etcd v0.5.0-alpha.5.0.20200207141613-5c5f4390b19e
)

require (
	chainmaker.org/chainmaker/common/v2 v2.3.3
	github.com/Azure/azure-pipeline-go v0.2.2 // indirect
	github.com/Azure/azure-storage-blob-go v0.7.0
	github.com/Azure/go-autorest/autorest/adal v0.8.0 // indirect
	github.com/Beyond-simplechain/foundation v1.0.0
	github.com/Jeffail/tunny v0.0.0-20190930221602-f13eb662a36a
	github.com/StackExchange/wmi v0.0.0-20180116203802-5d049714c4a6 // indirect
	github.com/VictoriaMetrics/fastcache v1.5.3
	github.com/aristanetworks/goarista v0.0.0-20190924011532-60b7b74727fd
	github.com/bits-and-blooms/bitset v1.11.0
	github.com/btcsuite/btcd v0.21.0-beta
	github.com/cespare/cp v0.1.0
	github.com/cespare/xxhash v1.1.0
	github.com/coreos/etcd v3.3.18+incompatible
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc
	github.com/deckarep/golang-set v0.0.0-20180603214616-504e848d77ea
	github.com/docker/docker v1.4.2-0.20180625184442-8e610b2b55bf
	github.com/eapache/channels v1.1.0
	github.com/edsrzf/mmap-go v1.0.0
	github.com/elastic/gosigar v0.8.1-0.20180330100440-37f05ff46ffa
	github.com/exascience/pargo v1.1.0
	github.com/fatih/color v1.14.1
	github.com/fjl/memsize v0.0.0-20180418122429-ca190fb6ffbc
	github.com/gballet/go-libpcsclite v0.0.0-20190607065134-2772fd86a8ff
	github.com/go-ole/go-ole v1.2.1 // indirect
	github.com/go-stack/stack v1.8.0
	github.com/golang/protobuf v1.5.3
	github.com/golang/snappy v0.0.4
	github.com/gorilla/websocket v1.4.3-0.20220104015952-9111bb834a68
	github.com/graph-gophers/graphql-go v0.0.0-20191115155744-f33e81362277
	github.com/hashicorp/golang-lru v0.5.4
	github.com/huin/goupnp v0.0.0-20161224104101-679507af18f3
	github.com/influxdata/influxdb v1.2.3-0.20180221223340-01288bdb0883
	github.com/jackpal/go-nat-pmp v1.0.2-0.20160603034137-1fa385a6f458
	github.com/julienschmidt/httprouter v1.3.0
	github.com/karalabe/usb v0.0.0-20190919080040-51dc0efba356
	github.com/kilic/bls12-381 v0.1.0
	github.com/mattn/go-colorable v0.1.13
	github.com/mattn/go-isatty v0.0.17
	github.com/mattn/go-runewidth v0.0.4 // indirect
	github.com/miekg/pkcs11 v1.1.1
	github.com/mr-tron/base58 v1.2.0
	github.com/naoina/go-stringutil v0.1.0 // indirect
	github.com/naoina/toml v0.1.2-0.20170918210437-9fafd6967416
	github.com/olekukonko/tablewriter v0.0.2-0.20190409134802-7e037d187b0c
	github.com/panjf2000/ants/v2 v2.4.3
	github.com/pborman/uuid v1.2.0
	github.com/peterh/liner v1.1.1-0.20190123174540-a2c9a5303de7
	github.com/pkg/errors v0.9.1
	github.com/prometheus/tsdb v0.7.1
	github.com/rjeczalik/notify v0.9.1
	github.com/robertkrimen/otto v0.0.0-20170205013659-6a77b7cbc37d
	github.com/rs/cors v1.7.0
	github.com/satori/go.uuid v1.2.0
	github.com/smartystreets/goconvey v1.8.1
	github.com/spf13/viper v1.18.2
	github.com/status-im/keycard-go v0.0.0-20190316090335-8537d3370df4
	github.com/steakknife/bloomfilter v0.0.0-20180922174646-6819c0d2a570
	github.com/steakknife/hamming v0.0.0-20180906055917-c99c65617cd3 // indirect
	github.com/stretchr/testify v1.8.4
	github.com/syndtr/goleveldb v1.0.1-0.20200815110645-5c35d600f0ca
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common v1.0.873
	github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/kms v1.0.873
	github.com/tjfoc/gmsm v1.4.1
	github.com/tyler-smith/go-bip39 v1.0.1-0.20181017060643-dbb3b84ba2ef
	github.com/wsddn/go-ecdh v0.0.0-20161211032359-48726bab9208
	golang.org/x/crypto v0.16.0
	golang.org/x/net v0.19.0
	golang.org/x/sync v0.5.0
	golang.org/x/sys v0.15.0
	golang.org/x/text v0.14.0
	google.golang.org/grpc v1.59.0
	gopkg.in/natefinch/npipe.v2 v2.0.0-20160621034901-c1b8fa8bdcce
	gopkg.in/olebedev/go-duktape.v3 v3.0.0-20200619000410-60c24ae608a6
	gopkg.in/oleiade/lane.v1 v1.0.0
	gopkg.in/sourcemap.v1 v1.0.5 // indirect
	gopkg.in/urfave/cli.v1 v1.20.0
	gotest.tools v2.2.0+incompatible
)

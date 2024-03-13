// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package permission

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/bigzoro/my_simplechain"
	"github.com/bigzoro/my_simplechain/accounts/abi"
	"github.com/bigzoro/my_simplechain/accounts/abi/bind"
	"github.com/bigzoro/my_simplechain/common"
	"github.com/bigzoro/my_simplechain/core/types"
	"github.com/bigzoro/my_simplechain/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
)

// StoreAbiMetaData contains all meta data concerning the StoreAbi contract.
var StoreAbiMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"}],\"name\":\"getAbi\",\"outputs\":[{\"internalType\":\"address\",\"name\":\"\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"string\",\"name\":\"name\",\"type\":\"string\"},{\"internalType\":\"address\",\"name\":\"addr\",\"type\":\"address\"},{\"internalType\":\"string\",\"name\":\"_abi\",\"type\":\"string\"}],\"name\":\"set\",\"outputs\":[],\"stateMutability\":\"payable\",\"type\":\"function\"}]",
	Sigs: map[string]string{
		"8d717ac5": "getAbi(string)",
		"1ff5020f": "set(string,address,string)",
	},
	Bin: "0x608060405234801561001057600080fd5b50610604806100206000396000f3fe6080604052600436106100295760003560e01c80631ff5020f1461002e5780638d717ac51461016e575b600080fd5b61016c6004803603606081101561004457600080fd5b81019060208101813564010000000081111561005f57600080fd5b82018360208201111561007157600080fd5b8035906020019184600183028401116401000000008311171561009357600080fd5b91908080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092956001600160a01b038535169590949093506040810192506020013590506401000000008111156100f757600080fd5b82018360208201111561010957600080fd5b8035906020019184600183028401116401000000008311171561012b57600080fd5b91908080601f0160208091040260200160405190810160405280939291908181526020018383808284376000920191909152509295506102b2945050505050565b005b34801561017a57600080fd5b506102216004803603602081101561019157600080fd5b8101906020810181356401000000008111156101ac57600080fd5b8201836020820111156101be57600080fd5b803590602001918460018302840111640100000000831117156101e057600080fd5b91908080601f01602080910402602001604051908101604052809392919081815260200183838082843760009201919091525092955061039c945050505050565b60405180836001600160a01b03166001600160a01b0316815260200180602001828103825283818151815260200191508051906020019080838360005b8381101561027657818101518382015260200161025e565b50505050905090810190601f1680156102a35780820380516001836020036101000a031916815260200191505b50935050505060405180910390f35b6102ba610509565b6040518060600160405280858152602001846001600160a01b03168152602001838152509050806000856040518082805190602001908083835b602083106103135780518252601f1990920191602091820191016102f4565b51815160209384036101000a600019018019909216911617905292019485525060405193849003810190932084518051919461035494508593500190610533565b506020828101516001830180546001600160a01b0319166001600160a01b03909216919091179055604083015180516103939260028501920190610533565b50505050505050565b600060606000836040518082805190602001908083835b602083106103d25780518252601f1990920191602091820191016103b3565b51815160209384036101000a600019018019909216911617905292019485525060405193849003810184206001015487516001600160a01b039091169460009450889350918291908401908083835b602083106104405780518252601f199092019160209182019101610421565b518151600019602094850361010090810a8201928316921993909316919091179092529490920196875260408051978890038201882060029081018054601f60018216159098029095019094160494850182900482028801820190528387529095945085935084019050828280156104f95780601f106104ce576101008083540402835291602001916104f9565b820191906000526020600020905b8154815290600101906020018083116104dc57829003601f168201915b5050505050905091509150915091565b60405180606001604052806060815260200160006001600160a01b03168152602001606081525090565b828054600181600116156101000203166002900490600052602060002090601f016020900481019282601f1061057457805160ff19168380011785556105a1565b828001600101855582156105a1579182015b828111156105a1578251825591602001919060010190610586565b506105ad9291506105b1565b5090565b6105cb91905b808211156105ad57600081556001016105b7565b9056fea2646970667358221220b19ff616d9f9043c3428af7c961104e69172469a24c0cf1382bd1f88dde93a7c64736f6c63430006000033",
}

// StoreAbiABI is the input ABI used to generate the binding from.
// Deprecated: Use StoreAbiMetaData.ABI instead.
var StoreAbiABI = StoreAbiMetaData.ABI

// Deprecated: Use StoreAbiMetaData.Sigs instead.
// StoreAbiFuncSigs maps the 4-byte function signature to its string representation.
var StoreAbiFuncSigs = StoreAbiMetaData.Sigs

// StoreAbiBin is the compiled bytecode used for deploying new contracts.
// Deprecated: Use StoreAbiMetaData.Bin instead.
var StoreAbiBin = StoreAbiMetaData.Bin

// DeployStoreAbi deploys a new Ethereum contract, binding an instance of StoreAbi to it.
func DeployStoreAbi(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, *StoreAbi, error) {
	parsed, err := StoreAbiMetaData.GetAbi()
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	if parsed == nil {
		return common.Address{}, nil, nil, errors.New("GetABI returned nil")
	}

	address, tx, contract, err := bind.DeployContract(auth, *parsed, common.FromHex(StoreAbiBin), backend)
	if err != nil {
		return common.Address{}, nil, nil, err
	}
	return address, tx, &StoreAbi{StoreAbiCaller: StoreAbiCaller{contract: contract}, StoreAbiTransactor: StoreAbiTransactor{contract: contract}, StoreAbiFilterer: StoreAbiFilterer{contract: contract}}, nil
}

// StoreAbi is an auto generated Go binding around an Ethereum contract.
type StoreAbi struct {
	StoreAbiCaller     // Read-only binding to the contract
	StoreAbiTransactor // Write-only binding to the contract
	StoreAbiFilterer   // Log filterer for contract events
}

// StoreAbiCaller is an auto generated read-only Go binding around an Ethereum contract.
type StoreAbiCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StoreAbiTransactor is an auto generated write-only Go binding around an Ethereum contract.
type StoreAbiTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StoreAbiFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type StoreAbiFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// StoreAbiSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type StoreAbiSession struct {
	Contract     *StoreAbi         // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// StoreAbiCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type StoreAbiCallerSession struct {
	Contract *StoreAbiCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts   // Call options to use throughout this session
}

// StoreAbiTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type StoreAbiTransactorSession struct {
	Contract     *StoreAbiTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts   // Transaction auth options to use throughout this session
}

// StoreAbiRaw is an auto generated low-level Go binding around an Ethereum contract.
type StoreAbiRaw struct {
	Contract *StoreAbi // Generic contract binding to access the raw methods on
}

// StoreAbiCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type StoreAbiCallerRaw struct {
	Contract *StoreAbiCaller // Generic read-only contract binding to access the raw methods on
}

// StoreAbiTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type StoreAbiTransactorRaw struct {
	Contract *StoreAbiTransactor // Generic write-only contract binding to access the raw methods on
}

// NewStoreAbi creates a new instance of StoreAbi, bound to a specific deployed contract.
func NewStoreAbi(address common.Address, backend bind.ContractBackend) (*StoreAbi, error) {
	contract, err := bindStoreAbi(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &StoreAbi{StoreAbiCaller: StoreAbiCaller{contract: contract}, StoreAbiTransactor: StoreAbiTransactor{contract: contract}, StoreAbiFilterer: StoreAbiFilterer{contract: contract}}, nil
}

// NewStoreAbiCaller creates a new read-only instance of StoreAbi, bound to a specific deployed contract.
func NewStoreAbiCaller(address common.Address, caller bind.ContractCaller) (*StoreAbiCaller, error) {
	contract, err := bindStoreAbi(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &StoreAbiCaller{contract: contract}, nil
}

// NewStoreAbiTransactor creates a new write-only instance of StoreAbi, bound to a specific deployed contract.
func NewStoreAbiTransactor(address common.Address, transactor bind.ContractTransactor) (*StoreAbiTransactor, error) {
	contract, err := bindStoreAbi(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &StoreAbiTransactor{contract: contract}, nil
}

// NewStoreAbiFilterer creates a new log filterer instance of StoreAbi, bound to a specific deployed contract.
func NewStoreAbiFilterer(address common.Address, filterer bind.ContractFilterer) (*StoreAbiFilterer, error) {
	contract, err := bindStoreAbi(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &StoreAbiFilterer{contract: contract}, nil
}

// bindStoreAbi binds a generic wrapper to an already deployed contract.
func bindStoreAbi(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := abi.JSON(strings.NewReader(StoreAbiABI))
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_StoreAbi *StoreAbiRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _StoreAbi.Contract.StoreAbiCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_StoreAbi *StoreAbiRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _StoreAbi.Contract.StoreAbiTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_StoreAbi *StoreAbiRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _StoreAbi.Contract.StoreAbiTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_StoreAbi *StoreAbiCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _StoreAbi.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_StoreAbi *StoreAbiTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _StoreAbi.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_StoreAbi *StoreAbiTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _StoreAbi.Contract.contract.Transact(opts, method, params...)
}

// GetAbi is a free data retrieval call binding the contract method 0x8d717ac5.
//
// Solidity: function getAbi(string name) view returns(address, string)
func (_StoreAbi *StoreAbiCaller) GetAbi(opts *bind.CallOpts, name string) (common.Address, string, error) {
	var out []interface{}
	err := _StoreAbi.contract.Call(opts, &out, "getAbi", name)

	if err != nil {
		return *new(common.Address), *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(common.Address)).(*common.Address)
	out1 := *abi.ConvertType(out[1], new(string)).(*string)

	return out0, out1, err

}

// GetAbi is a free data retrieval call binding the contract method 0x8d717ac5.
//
// Solidity: function getAbi(string name) view returns(address, string)
func (_StoreAbi *StoreAbiSession) GetAbi(name string) (common.Address, string, error) {
	return _StoreAbi.Contract.GetAbi(&_StoreAbi.CallOpts, name)
}

// GetAbi is a free data retrieval call binding the contract method 0x8d717ac5.
//
// Solidity: function getAbi(string name) view returns(address, string)
func (_StoreAbi *StoreAbiCallerSession) GetAbi(name string) (common.Address, string, error) {
	return _StoreAbi.Contract.GetAbi(&_StoreAbi.CallOpts, name)
}

// Set is a paid mutator transaction binding the contract method 0x1ff5020f.
//
// Solidity: function set(string name, address addr, string _abi) payable returns()
func (_StoreAbi *StoreAbiTransactor) Set(opts *bind.TransactOpts, name string, addr common.Address, _abi string) (*types.Transaction, error) {
	return _StoreAbi.contract.Transact(opts, "set", name, addr, _abi)
}

// Set is a paid mutator transaction binding the contract method 0x1ff5020f.
//
// Solidity: function set(string name, address addr, string _abi) payable returns()
func (_StoreAbi *StoreAbiSession) Set(name string, addr common.Address, _abi string) (*types.Transaction, error) {
	return _StoreAbi.Contract.Set(&_StoreAbi.TransactOpts, name, addr, _abi)
}

// Set is a paid mutator transaction binding the contract method 0x1ff5020f.
//
// Solidity: function set(string name, address addr, string _abi) payable returns()
func (_StoreAbi *StoreAbiTransactorSession) Set(name string, addr common.Address, _abi string) (*types.Transaction, error) {
	return _StoreAbi.Contract.Set(&_StoreAbi.TransactOpts, name, addr, _abi)
}

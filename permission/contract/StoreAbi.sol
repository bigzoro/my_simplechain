pragma solidity >=0.4.22 <0.7.0;

contract StoreAbi {
    struct contractAbi {
        string name;//contract name
        address addr;//contract address
        string abi;//contract abi
    }
    mapping(string => contractAbi) abiMap;
    function getAbi(string memory name) public view returns (address, string memory) {
        return (abiMap[name].addr, abiMap[name].abi);
    }
    function set(string memory name, address addr, string memory _abi) public payable {
        contractAbi memory ca = contractAbi(name, addr, _abi);
        abiMap[name] = ca;
    }
}
pragma solidity >=0.4.22 <0.7.0;
//约定命名下横线的方法为内部方法
//nodeId格式为：
//enode://98d1fb92def94a3b8a861c7b1837aa9364126f5f12368db9194f0e152490277da8d5351a3e4796c10faf6c6af16a2185b5cb0a119d05111864eb284875f0bbe9
//加入网络：0；剔除网络：1；升级：2；降级：3
/**
 * @title Permission
 */
contract Permission {
    //联盟创始节点不允许退出联盟
    //联盟创始节点
    uint private constant originator=2;
    //管理节点
    uint  private constant admin=2;
    //普通节点
    uint  private constant common=0;
    //游离节点
    uint  private constant isolated=1;
    // 0 加入联盟
    string  private constant opJoin="0";
    // 1 退出联盟
    string  private constant opExit="1";
    // 2 升级为管理节点
    string  private constant opAdmin="2";
    // 3 降级成普通节点
    string  private constant opCommon="3";

    // events related
    event AddNewNodeNotify(string enodeId, string ip, string port);

    event VerifyNotify(string enodeId,uint opCode,string ip, string port);

    event ApplyByAdminNotify(string enodeId);

    event networkInitComplete(uint number,uint timestamp);

    event isVotedEvent(string  _nodeId,string  _opCode, string  _voterNodeId);

    event isAdminRoleEvent(string _nodeId,address _sender);

    //控制网络初始化的变量，就是整个网络有个初始化的过程，初始化完成之前，admin的节点是随便添加的
    //初始化完成之后，添加节点都是需要经过投票的。
    bool  private  networkStatus = false;

    //管理员的数量
    uint private adminCount; //administrator count

    struct Node {
        string nodeId;//节点id
        string ip;//节点ip地址
        string port;//节点端口
        string nodeName;//节点名称
        address nodeAddress; //节点账号地址
        bool isOriginator;  //是否创始人,联盟创世参与者，创世参与者不允许退出联盟
        // 0 表示普通节点
        // 1 表示游离节点
        // 2 表示管理节点
        uint role;
        uint createdAt ;
        //表示的是纳入管理，就是说要投票加入了，那么就为true,退出网络就为false
        bool exist ; //存在性标志,添加时设置为true,退出网络时设置为false,这样就可以反复利用
    }
    //Used to count votes--统计投票数据
    struct Statistics {
        bool exist ; //存在性标志
        //节点
        string nodeId;
        //同意票数
        uint agree;
        //不同意票数
        uint disagree;
        //发起提案的节点
        string proposeNodeId;
        // 0 加入联盟
        // 1 退出联盟
        // 2 升级为管理节点
        // 3 降级成普通节点
        string opCode;
        //投票完成状态，
        // 0：未完成；
        // 1：已完成
        uint status;
    }
    //投票记录
    struct VoteRecord {
        //投票对象
        string nodeId;
        //投票人
        string voterNodeId;
        //投票人地址
        address voterAddress;
        //投票针对的操作
        string opCode;
        //投同意票，还是投反对票
        //赞成:true，反对:false
        bool auth;
    }

    //节点都在nodeMap 中（包括游离节点、普通节点、管理节点）
    //在网络中或曾加入网络的节点信息，key:hash(nodeId)
    mapping(bytes32 => Node)  private nodeMap;

    //存在的节点
    mapping(bytes32 => bool)  private existNodeIds;

    //用来保存节点的id
    bytes[] private nodeIds;//store nodeId

    address[] private originators;

    //统计票数的记录，key:hash(nodeId+opCode)
    mapping(bytes32 => Statistics)  private statisticsMap;

    //投票记录
    VoteRecord[] private voteRecords;

    //对于每一次投票，记录投过票的管理员节点，key:hash(nodeId+opCode)
    //string[] 投票者集合
    mapping(bytes32 => string[]) private voterMap;

    modifier checkNetworkStatus() {
        require(!networkStatus, "can not set admin node,initialize finished.");
        _;
    }
    modifier checkInitStatus() {
        require(networkStatus, "can not invoke method except setAdmin function,initialize have not finished.");
        _;
    }
    //节点移除、节点升级、节点降级
    //都走这个方法
    // opCode 3为降级
    // opCode 2为升级
    // opCode 1为移除
    //add node to blacklist application
    function makeProposeForRoleChange(string memory _nodeId, string memory _opCode,string memory _voterNodeId) checkInitStatus() public payable {
        require(_isAdminRole(_voterNodeId,msg.sender), "the role is not admin!");
        if (_strEqual(_opCode,opExit) || _strEqual(_opCode,opCommon)) {//如果操作类型是剔除网络或者降级
            bytes32  nodeHash = hash256(bytes(_nodeId));
            Node memory nt = nodeMap[nodeHash];
            require(!nt.isOriginator, "主节点不允许退出");
        }
        require(_validatePropose(_nodeId, _opCode), "申请失败");
        bytes32 statKey = _buildStatMapKey(_nodeId,_opCode);
        Statistics memory statistics = Statistics(true,_nodeId, 0,0, _voterNodeId, _opCode,uint(0));
        statisticsMap[statKey]=statistics;
        //清空投票信息
        delete voterMap[statKey];

        emit ApplyByAdminNotify(_nodeId);
    }
    //不允许剔除已被剔除的节点，不允许升级已升级的节点，不允许降级已降级的节点
    function _validatePropose(string memory _nodeId, string memory _opCode) internal view returns(bool) {
        if (_strEqual(_opCode, opJoin)) {
            return false;
        }
        bytes32 nodeHash = hash256(bytes(_nodeId));
        if (bytes(nodeMap[nodeHash].nodeId).length != 0) {
            if (nodeMap[nodeHash].role == isolated) {
                return false;
            }
            if (_strEqual(_opCode, opAdmin) && nodeMap[nodeHash].role == admin) {
                return false;
            }
            if (_strEqual(_opCode, opCommon) && nodeMap[nodeHash].role == common) {
                return false;
            }
        }
        return true;
    }
    //投赞成票
    function voteForRoleChange(string memory _nodeId, string memory _voterNodeId,string memory _opCode) checkInitStatus() public payable {
        if (!_isAdminRole(_voterNodeId,msg.sender)){
            emit isAdminRoleEvent(_voterNodeId,msg.sender);
        }
        require(_isAdminRole(_voterNodeId,msg.sender), "the role is must be admin!");//the verify node must be admin role.
        if (_isVoted(_nodeId, _opCode,_voterNodeId)){
            emit isVotedEvent(_nodeId, _opCode,_voterNodeId);
        }
        require(!_isVoted(_nodeId, _opCode,_voterNodeId),"已经投过票");
        if(_strEqual(_opCode,opAdmin)){
            //common=>admin
            //必须是普通节点才可以升级到管理节点
            require(_isCommonRole(_nodeId), "the node must be normal role");//if node is not normal role, it cann't upgrade.
            //更新票数
            Statistics memory statistics = _updateStatistic(_nodeId, _opCode,_voterNodeId,msg.sender);
            //获取赞成票数
            uint count = uint(statistics.agree);
            //保存投票者信息
            _insertVoter(_nodeId,_opCode, _voterNodeId);
            //当满足半数以上规则且投票未结束才可更新节点角色
            if (count > adminCount / 2 && statistics.status == 0) {
                //更新投票状态，投票完成
                bytes32 statKeyHash = hash256(bytes(_strConcat(_nodeId,_opCode)));
                _finishStatStatus(statKeyHash);
                delete voterMap[statKeyHash];
                //更新角色(common=>admin)
                bytes32 nodeHash = hash256(bytes(_nodeId));
                nodeMap[nodeHash].role = admin;
                adminCount++;
                emit VerifyNotify(_nodeId,admin,nodeMap[nodeHash].ip,nodeMap[nodeHash].port);
            }
        }else if(_strEqual(_opCode,opCommon)){
            bytes32 keyHash=hash256(bytes(_nodeId));
            //admin=>common
            require(isAdmin(keyHash), "the node must be admin!");//the apply node must be admin role.
            //更新票数
            Statistics memory statistics = _updateStatistic(_nodeId, _opCode,_voterNodeId,msg.sender);
            //获取赞成票数
            uint count = uint(statistics.agree);
            //保存投票者信息
            _insertVoter(_nodeId,_opCode, _voterNodeId);
            if (count > adminCount / 2 && statistics.status == 0) {//当满足半数以上规则且投票未结束才可更新节点角色
                //更新投票状态，投票完成
                bytes32 statKeyHash = hash256(bytes(_strConcat(_nodeId,_opCode)));
                _finishStatStatus(statKeyHash);
                delete voterMap[statKeyHash]; //删除投票过程
                //更新角色(admin=>common)
                bytes32 nodeHash = hash256(bytes(_nodeId));
                nodeMap[nodeHash].role = common;
                adminCount--;
                emit VerifyNotify(_nodeId,common,nodeMap[nodeHash].ip,nodeMap[nodeHash].port);
            }

        }else if(_strEqual(_opCode,opExit)){

            //更新票数
            Statistics memory statistics = _updateStatistic(_nodeId, _opCode,_voterNodeId,msg.sender);
            //获取赞成票数
            uint count = uint(statistics.agree);
            //保存投票者信息
            _insertVoter(_nodeId,_opCode, _voterNodeId);
            //当满足半数以上规则且投票未结束才可更新节点角色
            if (count > adminCount / 2 && statistics.status == 0) {
                //更新投票状态
                bytes32 statKeyHash = hash256(bytes(_strConcat(_nodeId,_opCode)));
                _finishStatStatus(statKeyHash);
                delete voterMap[statKeyHash]; //删除投票过程
                bytes32 nodeHash = hash256(bytes(_nodeId));
                if (nodeMap[nodeHash].role == admin) {
                    adminCount--;
                }
                //更新角色(admin,common=>isolated)
                nodeMap[nodeHash].role = isolated;
                nodeMap[nodeHash].exist=false;
                emit VerifyNotify(_nodeId,isolated,nodeMap[nodeHash].ip,nodeMap[nodeHash].port);
            }
        }
    }



    //获取管理员个数
    function getAdminCount() public view returns (uint) {
        return adminCount;
    }
    //tools function
    function hash256(bytes memory _hashStr) internal pure returns (bytes32) {
        return keccak256(_hashStr);
    }

    function isAdmin(bytes32 _nodeHash) public view returns (bool) {
        if(nodeMap[_nodeHash].exist){
            return nodeMap[_nodeHash].role == admin;
        }
        return false;
    }
    function _strConcat(string memory _a, string memory _b) internal pure returns (string memory){
        bytes memory _ba = bytes(_a);
        bytes memory _bb = bytes(_b);
        string memory ret = new string(_ba.length + _bb.length);
        bytes memory bret = bytes(ret);
        uint k = 0;
        for (uint i = 0; i < _ba.length; i++)bret[k++] = _ba[i];
        for (uint i = 0; i < _bb.length; i++) bret[k++] = _bb[i];
        return string(ret);
    }

    //设置联盟创始节点
    function setAdminNode(string memory _nodeId, string memory _ip, string memory _port, string memory _nodeName, address _nodeAddress) public
    checkNetworkStatus() {
        bytes32 key = hash256(bytes(_nodeId));
        require(!isAdmin(key),"节点已经是联盟创始节点");
        nodeMap[key].nodeId = _nodeId;
        nodeMap[key].ip = _ip;
        nodeMap[key].port = _port;
        nodeMap[key].nodeName = _nodeName;
        nodeMap[key].role = admin;
        nodeMap[key].nodeAddress = _nodeAddress;
        nodeMap[key].isOriginator = true;//联盟创始节点
        nodeMap[key].createdAt=block.timestamp;
        nodeMap[key].exist=true;
        nodeIds.push(bytes(_nodeId));
        existNodeIds[key]=true;
        adminCount++;
        originators.push(_nodeAddress);
        emit VerifyNotify(_nodeId, admin,nodeMap[key].ip,nodeMap[key].port);
    }
    //执行完这个方法以后，就不能再添加联盟创世节点
    //After this method is executed, it is not allowed to modify the administrator
    function initFinish() public checkNetworkStatus() {
        if(adminCount>0){
            networkStatus = true;
            emit networkInitComplete(block.number,block.timestamp);
        }
    }
    function _strEqual(string memory s1, string memory s2) internal pure returns (bool) {
        return keccak256(abi.encode(s1))== keccak256(abi.encode(s2));
    }
    //check pass
    //query method
    //返回同一个类型的节点的nodeId的数组
    function getNodeByRole(uint _role) public view returns (string memory) {
        string memory ret = "";
        //只有 0 1 2 三个可能值
        if (_role>2){
            return ret;
        }
        for (uint i = 0; i < nodeIds.length; i++) {
            bytes32 key = hash256(nodeIds[i]);
            string memory nodeId = nodeMap[key].nodeId;
            uint role = nodeMap[key].role;
            if (role == _role) {
                ret = _strConcat(_strConcat(nodeId, ","), ret);
            }
        }
        return ret;
    }

    //check pass
    //根据节点nodeId返回节点详细信息
    function getNodeMap(string memory _nodeId) public view returns (string memory,string memory,string memory,string memory,address, uint,bool,uint) {
        bytes32 key = hash256(bytes(_nodeId));
        Node memory info = nodeMap[key];
        return (info.nodeId,info.ip,info.port,info.nodeName,info.nodeAddress,info.role,info.isOriginator,info.createdAt);

    }
    //check pass
    //根据节点名称返回节点详细信息
    function getInfoByName(string memory _nodeName) public view returns (string memory,string memory,string memory,string memory,address, uint,bool,uint) {
        for (uint i = 0; i < nodeIds.length; i++) {
            bytes32 key = hash256(nodeIds[i]);
            if (_strEqual(_nodeName, nodeMap[key].nodeName)) {
                Node memory info = nodeMap[key];
                return (info.nodeId,info.ip,info.port,info.nodeName,info.nodeAddress,info.role,info.isOriginator,info.createdAt);
            }
        }
        return ("","","","",address(0),0,false,0);
    }
    //check pass
    //初始的管理员是否已经完成
    function isInitFinished() public view returns (bool) {
        return networkStatus;
    }
    //add new node application
    //申请添加新节点
    function makeProposeForAddNewNode(string memory _nodeId, string memory _ip, string memory _port, string memory nodeName, address _nodeAddress, string memory _proposeNodeId) checkInitStatus() public payable {

        bytes32 statKey = _buildStatMapKey(_nodeId, opJoin);

        bytes32 nodeHash = hash256(bytes(_nodeId));

        require(!(nodeMap[nodeHash].exist),"节点已经存在");

        Statistics memory statistics = Statistics(true,_nodeId, 0,0, _proposeNodeId, opJoin,uint(0));

        statisticsMap[statKey]=statistics;

        //将节点作为游离节点加入到nodeMap中,isolated表示游离节点
        _insertNodeMap(_nodeId, _ip, _port, nodeName, _nodeAddress, isolated, nodeHash);
        //提交事件
        emit AddNewNodeNotify(_nodeId, _ip, _port);
    }
    //给申请的节点投票
    function voteForNewNodeApply(string memory _nodeId, string memory _voterNodeId)checkInitStatus() public payable {
        if (!_isAdminRole(_voterNodeId,msg.sender)){
            emit isAdminRoleEvent(_voterNodeId,msg.sender);
        }
        require(_isAdminRole(_voterNodeId,msg.sender), "the role is not admin!");

        if (_isVoted(_nodeId, opJoin,_voterNodeId)){
            emit isVotedEvent(_nodeId, opJoin,_voterNodeId);
        }
        require(!_isVoted(_nodeId, opJoin,_voterNodeId),"已经投过票");

        Statistics memory statistics = _updateStatistic(_nodeId,opJoin,_voterNodeId,msg.sender);

        _insertVoter(_nodeId, opJoin, _voterNodeId);//保存投票者信息

        uint count = uint(statistics.agree);
        if (count > adminCount / 2 && statistics.status == 0) {//当满足半数以上规则且投票未结束才可更新节点角色
            bytes32 statKeyHash = _buildStatMapKey(_nodeId,opJoin);
            bytes32 nodeHash = hash256(bytes(_nodeId));
            _finishStatStatus(statKeyHash);//更新投票状态
            delete voterMap[statKeyHash]; //删除投票过程
            //更新节点角色（role）
            nodeMap[nodeHash].role = common;
            emit VerifyNotify(_nodeId, common,nodeMap[nodeHash].ip,nodeMap[nodeHash].port);
        }
    }
    //插入nodeMap中
    function _insertNodeMap(string memory _nodeId, string memory _ip, string memory _port, string memory _nodeName, address _nodeAddress, uint _role, bytes32 _nodeHash) internal {
        nodeMap[_nodeHash].ip = _ip;
        nodeMap[_nodeHash].port = _port;
        nodeMap[_nodeHash].nodeId = _nodeId;
        nodeMap[_nodeHash].nodeAddress = _nodeAddress;
        nodeMap[_nodeHash].nodeName = _nodeName;
        nodeMap[_nodeHash].role = _role;
        nodeMap[_nodeHash].isOriginator=false;
        nodeMap[_nodeHash].createdAt=block.timestamp;
        nodeMap[_nodeHash].exist=true;
        //保持唯一性
        if (!existNodeIds[_nodeHash]){
            nodeIds.push(bytes(_nodeId));
            existNodeIds[_nodeHash]=true;
        }
    }

    //检查是否管理角色
    function _isAdminRole(string memory _nodeId,address _sender) internal view returns (bool) {
        bytes32 keyHash = hash256(bytes(_nodeId));
        if (!isAdmin(keyHash))
        {
            return false;
        }
        return nodeMap[keyHash].nodeAddress == _sender;
    }
    //检查给定节点是游离节点
    function _isIsolatedRole(string memory _nodeId) internal view returns (bool) {
        bytes32 key = hash256(bytes(_nodeId));
        bool f1 = existNodeIds[key];
        bool f2 = nodeMap[key].role == isolated;
        return (f1&&f2)||!f1;
    }

    //检查给定节点是普通节点
    function _isCommonRole(string memory _nodeId) internal  view returns (bool) {
        bytes32 key = hash256(bytes(_nodeId));
        bool f1 = existNodeIds[key];
        bool f2 = nodeMap[key].role == common;
        return (f1&&f2);
    }

    function _updateStatistic(string memory _nodeId,string memory _opCode, string memory _voterNodeId, address _voterAddress) internal returns (Statistics memory) {
        bytes32 statKeyHash = _buildStatMapKey(_nodeId, _opCode);
        VoteRecord memory record=VoteRecord(_nodeId, _voterNodeId, _voterAddress,_opCode,true);
        voteRecords.push(record);
        Statistics memory statistics = statisticsMap[statKeyHash];
        statistics.agree += 1;
        statisticsMap[statKeyHash] = statistics;
        return statistics;
    }
    function _buildStatMapKey(string memory _eNodeStr, string memory opCode) internal pure returns (bytes32) {
        string memory statKey = _strConcat(_eNodeStr, opCode);
        return hash256(bytes(statKey));
    }
    function _finishStatStatus(bytes32 statKeyHash) internal {
        Statistics memory statistics = statisticsMap[statKeyHash];
        statistics.status = 1;
        statisticsMap[statKeyHash] = statistics;
    }
    function _insertVoter(string memory _nodeId,string memory _opCode, string memory _voterNodeId) internal {
        bytes32 key = hash256(bytes(_strConcat(_nodeId,_opCode)));
        voterMap[key].push(_voterNodeId);
    }
    //根据state key 获取投票统计信息
    function getLastStatistics(string memory _nodeId, string memory _opCode) public view returns (uint, uint,string memory, string memory, uint) {
        string memory key = _strConcat(_nodeId, _opCode);
        bytes32 nodeHash= hash256(bytes(key));
        Statistics memory statistics = statisticsMap[nodeHash];
        return (statistics.agree,statistics.disagree,statistics.proposeNodeId,statistics.opCode,statistics.status);
    }
    //查询所有投票未完成的记录，返回字符串（enodeId+opType），以逗号分割
    function getAllStatingRecord() public view  returns (string memory) {
        string memory result = "";
        for (uint i=0;i<nodeIds.length;i++) {
            bytes32 nodeHash = hash256(bytes(nodeIds[i]));
            string memory record = _getStatingRecord(nodeHash);
            if (!_strEqual(record, "")) {
                result = _strConcat(result, _strConcat(",", record));
            }
        }
        return result;
    }
    function _getStatingRecord(bytes32 _nodeHash) internal view returns (string memory) {
        string memory result = "";
        string memory nodeId = nodeMap[_nodeHash].nodeId;
        string memory tmp = _findStatingStatus(nodeId, opJoin);
        if (!_strEqual(tmp, "")) {
            result = tmp;
        }
        tmp = _findStatingStatus(nodeId, opExit);
        if (!_strEqual(tmp, "")) {
            result = _strConcat(result, _strConcat(",", tmp));
        }
        tmp = _findStatingStatus(nodeId, opAdmin);
        if (!_strEqual(tmp, "")) {
            result = _strConcat(result, _strConcat(",", tmp));
        }
        tmp = _findStatingStatus(nodeId, opCommon);
        if (!_strEqual(tmp, "")) {
            result = _strConcat(result, _strConcat(",", tmp));
        }
        return result;
    }
    function _findStatingStatus(string memory _nodeId, string memory _opCode) internal view returns (string memory) {
        bytes32 key = _buildStatMapKey(_nodeId, _opCode);
        if (!statisticsMap[key].exist) {
            return "";
        }
        Statistics memory statistics = statisticsMap[key];
        //投票还在进行中，未完成
        if (statistics.status == 0) {
            return _strConcat(_nodeId, _opCode);
        }
        return "";
    }
    //投反对票
    //包括加入，升级，降级，退出
    function disagree(string memory _nodeId, string memory _voterNodeId,string memory _opCode) checkInitStatus() public payable {
        require(_isAdminRole(_voterNodeId,msg.sender), "the role must be admin!");
        bytes32 statKeyHash = _buildStatMapKey(_nodeId, _opCode);
        Statistics memory statistics = statisticsMap[statKeyHash];
        // 新增投票记录
        _addDisagreeVote(_nodeId, _voterNodeId,msg.sender,_opCode);

        //增加反对票的数量
        statistics.disagree += 1;
        if (uint(statistics.disagree) > adminCount / 2 && statistics.status == 0) {
            statistics.status = 1;
            if(_strEqual(_opCode,opJoin)){
                nodeMap[hash256(bytes(_nodeId))].exist=false;
            }
            delete voterMap[statKeyHash]; //删除投票过程
        }
        statisticsMap[statKeyHash] = statistics;
    }
    function _addDisagreeVote(string memory _nodeId,string memory _voterNodeId,address _voterNodeAddress,string memory _opCode) internal {
        VoteRecord memory record;
        record.nodeId = _nodeId;
        record.voterNodeId = _voterNodeId;
        record.voterAddress = _voterNodeAddress;
        record.opCode=_opCode;
        record.auth = false;
        voteRecords.push(record);
        _insertVoter(_nodeId,_opCode, _voterNodeId);
    }
    //更新节点ip和端口信息
    function updateNodeInfo(string memory _nodeId,string memory _ip,string memory _port) public {
        bytes32 nodeHash = hash256(bytes(_nodeId));
        Node memory node = nodeMap[nodeHash];
        require((node.nodeAddress == msg.sender), "账号不匹配");
        node.ip = _ip;
        node.port = _port;
        nodeMap[nodeHash] = node;
    }
    //更新节点的名称
    function updateNodeName(string memory _nodeId,string memory _nodeName) public {
        bytes32 nodeHash = hash256(bytes(_nodeId));
        Node memory node = nodeMap[nodeHash];
        require((node.nodeAddress == msg.sender), "账号不匹配");
        node.nodeName = _nodeName;
        nodeMap[nodeHash] = node;
    }
    //退出网络，需要触发断开网络连接的事件，但主节点不允许退出
    function exit(string memory _nodeId) checkInitStatus() public {
        bytes32 key = hash256(bytes(_nodeId));
        if(nodeMap[key].exist==false){
            return ;
        }
        //校验是否已经退出网路
        Node memory nodeTable = nodeMap[key];
        require(!nodeTable.isOriginator, "主节点不允许退出");
        nodeMap[key].exist=false;
        emit VerifyNotify(_nodeId,  isolated,nodeMap[key].ip,nodeMap[key].port);
    }
    //查找该节点是否为本次申请投过票
    function _isVoted(string memory _nodeId,string memory _opCode, string memory _voterNodeId) internal view returns(bool){
        bytes32 key = hash256(bytes(_strConcat(_nodeId,_opCode)));
        string[] memory ids=voterMap[key];
        for(uint i=0;i<ids.length;i++){
            if(_strEqual(ids[i],_voterNodeId)){
                return true;
            }
        }
        return false;
    }
    function getOriginators() public view returns(address[] memory){
        return originators;
    }
    function nodeExists(string memory _nodeId) public view returns (bool) {
        bytes32 key = hash256(bytes(_nodeId));
        Node memory node = nodeMap[key];
        return node.exist;
    }
}
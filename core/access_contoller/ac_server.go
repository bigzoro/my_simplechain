package access_contoller

import (
	"fmt"
	"my_simplechain/core/access_contoller/my_lru"
	"my_simplechain/params"

	bcx509 "my_simplechain/core/access_contoller/crypto/x509"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

// Special characters allowed to define customized access rules
const (
	LIMIT_DELIMITER              = "/"
	PARAM_CERTS                  = "certs"
	PARAM_CERTHASHES             = "cert_hashes"
	PARAM_ALIASES                = "aliases"
	PARAM_ALIAS                  = "alias"
	PUBLIC_KEYS                  = "pubkey"
	unsupportedRuleErrorTemplate = "bad configuration: unsupported rule [%s]"
)

var (
	policyRead = newPolicy(
		RuleAny,
		nil,
		[]Role{
			RoleConsensusNode,
			RoleCommonNode,
			RoleClient,
			RoleAdmin,
		},
	)
	policySpecialRead = newPolicy(
		RuleAny,
		nil,
		[]Role{
			RoleConsensusNode,
			RoleCommonNode,
			RoleClient,
			RoleAdmin,
			RoleLight,
		},
	)

	policyWrite = newPolicy(
		RuleAny,
		nil,
		[]Role{
			RoleClient,
			RoleAdmin,
			RoleConsensusNode,
		},
	)

	licyAdmin = newPolicy(
		RuleAny,
		nil,
		[]Role{
			RoleAdmin,
		},
	)

	policySubscribe = newPolicy(
		RuleAny,
		nil,
		[]Role{
			RoleLight,
			RoleClient,
			RoleAdmin,
		},
	)

	policyConfig = newPolicy(
		RuleMajority,
		nil,
		[]Role{
			RoleAdmin,
		},
	)

	policyForbidden = newPolicy(
		RuleForbidden,
		nil,
		nil)
)

var restrainedResourceList = map[string]bool{
	//protocol.ResourceNameAllTest:       true,
	//protocol.ResourceNameP2p:           true,
	//protocol.ResourceNameConsensusNode: true,
	//
	//common.TxType_QUERY_CONTRACT.String():  true,
	//common.TxType_INVOKE_CONTRACT.String(): true,
	//common.TxType_SUBSCRIBE.String():       true,
	//common.TxType_ARCHIVE.String():         true,
}

var notEnoughParticipantsSupportError = "authentication fail: not enough participants support this action"

// 用于管理访问控制策略和成员验证的服务实例。
// 它包含了一些列字段，用于维护组织、策略映射、成员缓存以及其它与访问控制
// 和成员验证相关的配置
type accessControlService struct {
	// 注册到访问控制服务中的组织数量
	orgNum int32

	// 存储组织 ID 到组织实体的映射
	orgList *sync.Map // map[string]interface{} , orgId -> interface{}

	// 存储资源名称到访问控制策略的映射
	resourceNamePolicyMap *sync.Map // map[string]*policy , resourceName -> *policy

	// 存储资源名称到特殊策略的映射。特殊策略通常用于覆盖通用策略中的某些规则
	exceptionalPolicyMap *sync.Map // map[string]*policy , resourceName -> *policy

	// 用于存储资源名称到最新策略的映射，有助于追踪策略的更新
	lastestPolicyMap *sync.Map // map[string]*policy , resourceName -> *policy

	// 220 策略映射
	resourceNamePolicyMap220 *sync.Map
	exceptionalPolicyMap220  *sync.Map

	//local cache for member
	// 缓存成员对象。这个缓存有助于提高成员验证的效率，避免重复创建相同的成员对象
	memberCache *my_lru.Cache

	// 存储区块链数据的存储服务
	//dataStore  BlockchainStore

	//log  Logger

	// hash algorithm for chains
	// 链上使用的哈希算法
	hashType string

	// 认证类型
	authType string

	// 创建新的成员对象
	//pwkNewMember func(member *pbac.Member) ( Member, error)

	// 获取证书验证的选项
	getCertVerifyOptions func() *bcx509.VerifyOptions
}

type memberCached struct {
	member    MemberInterface
	certChain []*bcx509.Certificate
}

func initAccessControlService() *accessControlService {
	acService := &accessControlService{
		orgNum:                   0,
		orgList:                  &sync.Map{},
		resourceNamePolicyMap:    &sync.Map{},
		exceptionalPolicyMap:     &sync.Map{},
		lastestPolicyMap:         &sync.Map{},
		resourceNamePolicyMap220: &sync.Map{},
		exceptionalPolicyMap220:  &sync.Map{},
		//memberCache:              concurrentlru.New(localconf.ChainMakerConfig.NodeConfig.CertCacheSize),
		//dataStore:                store,
		//log:                      log,
		//hashType:                 hashType,
		//authType:                 authType,
	}

	return acService
}

func (acs *accessControlService) initResourcePolicy(resourcePolicies []*params.ResourcePolicy,
	localOrgId string) {
	acs.createDefaultResourcePolicy(localOrgId)
	lastestPolicyMap := &sync.Map{}
	for _, resourcePolicy := range resourcePolicies {
		if acs.validateResourcePolicy(resourcePolicy) {
			//policy := newPolicyFromPb(resourcePolicy.Policy)
			//policy = newPolicy()
			//lastestPolicyMap.Store(resourcePolicy.ResourceName, policy)
		}
	}
	acs.lastestPolicyMap = lastestPolicyMap
}

func (acs *accessControlService) createDefaultResourcePolicy(localOrgId string) {

	//policyArchive.orgList = []string{localOrgId}
	acs.resourceNamePolicyMap.Store(ResourceNameReadData, policyRead)
	acs.resourceNamePolicyMap.Store(ResourceNameWriteData, policyWrite)
	acs.resourceNamePolicyMap.Store(ResourceNameUpdateConfig, policyConfig)
}

func (acs *accessControlService) validateResourcePolicy(resourcePolicy *params.ResourcePolicy) bool {
	if _, ok := restrainedResourceList[resourcePolicy.ResourceName]; ok {
		//acs.log.Errorf("bad configuration: should not modify the access policy of the resource: %s",
		//	resourcePolicy.ResourceName)
		return false
	}

	if resourcePolicy == nil {
		//acs.log.Errorf("bad configuration: access principle should not be nil when modifying access control configurations")
		return false
	}

	//if !acs.checkResourcePolicyOrgList(&resourcePolicy.Policy) {
	//	return false
	//}
	//
	//return acs.checkResourcePolicyRule(resourcePolicy)

	return true
}

// 校验给定策略中的组织列表是否有效
func (acs *accessControlService) checkResourcePolicyOrgList(policy *policy) bool {
	// 记录已经检查过的组织
	//orgCheckList := map[string]bool{}
	//for _, org := range policy.OrgList {
	//	是否存在
	//if _, ok := acs.orgList.Load(org); !ok {
	//	acs.log.Errorf("bad configuration: configured organization list contains unknown organization [%s]", org)
	//	return false
	//} else if _, alreadyIn := orgCheckList[org]; alreadyIn { // 是否重复
	//	acs.log.Errorf("bad configuration: duplicated entries [%s] in organization list", org)
	//	return false
	//} else {
	//	orgCheckList[org] = true
	//}
	//}
	return true
}

// 校验策略的规则是否符合
func (acs *accessControlService) checkResourcePolicyRule(resourcePolicy *ResourcePolicy) bool {
	switch resourcePolicy.Policy.rule {
	case RuleAny, RuleAll, RuleForbidden:
		return true
	case RuleSelf:
		return acs.checkResourcePolicyRuleSelfCase(resourcePolicy)
	case RuleMajority:
		return acs.checkResourcePolicyRuleMajorityCase(&resourcePolicy.Policy)
	case RuleDelete:
		//acs.log.Debugf("delete policy configuration of %s", resourcePolicy.ResourceName)
		return true
	default:
		return acs.checkResourcePolicyRuleDefaultCase(&resourcePolicy.Policy)
	}
}

func (acs *accessControlService) checkResourcePolicyRuleSelfCase(resourcePolicy *ResourcePolicy) bool {
	switch resourcePolicy.ResourceName {
	//case syscontract.SystemContract_CHAIN_CONFIG.String() + "-" +
	//	syscontract.ChainConfigFunction_TRUST_ROOT_UPDATE.String(),
	//	syscontract.SystemContract_CHAIN_CONFIG.String() + "-" +
	//		syscontract.ChainConfigFunction_NODE_ID_UPDATE.String():
	//	return true
	//default:
	//acs.log.Errorf("bad configuration: the access rule of [%s] should not be [%s]", resourcePolicy.ResourceName,
	//	resourcePolicy.Policy.rule)
	//return false
	}

	return true
}

func (acs *accessControlService) checkResourcePolicyRuleMajorityCase(policy *policy) bool {
	if len(policy.orgList) != int(atomic.LoadInt32(&acs.orgNum)) {
		//acs.log.Warnf("[%s] rule considers all the organizations on the chain, any customized configuration for "+
		//	"organization list will be overridden, should use [Portion] rule for customized organization list",
		//	protocol.RuleMajority)
	}
	switch len(policy.roleList) {
	case 0:
		//acs.log.Warnf("role allowed in [%s] is [%s]", protocol.RuleMajority, protocol.RoleAdmin)
		return true
	case 1:
		//if policy.roleList[0] != string(RoleAdmin) {
		//	acs.log.Warnf("role allowed in [%s] is only [%s], [%s] will be overridden", protocol.RuleMajority,
		//		protocol.RoleAdmin, policy.RoleList[0])
		//}
		//return true
	default:
		//acs.log.Warnf("role allowed in [%s] is only [%s], the other roles in the list will be ignored",
		//	protocol.RuleMajority, protocol.RoleAdmin)
		//return true
	}

	return true
}

func (acs *accessControlService) checkResourcePolicyRuleDefaultCase(policy *policy) bool {
	//nums := strings.Split(policy.Rule, LIMIT_DELIMITER)
	//switch len(nums) {
	//case 1:
	//	_, err := strconv.Atoi(nums[0])
	//	if err != nil {
	//		acs.log.Errorf(unsupportedRuleErrorTemplate, policy.Rule)
	//		return false
	//	}
	//	return true
	//case 2:
	//	numerator, err := strconv.Atoi(nums[0])
	//	if err != nil {
	//		acs.log.Errorf(unsupportedRuleErrorTemplate, policy.Rule)
	//		return false
	//	}
	//	denominator, err := strconv.Atoi(nums[1])
	//	if err != nil {
	//		acs.log.Errorf(unsupportedRuleErrorTemplate, policy.Rule)
	//		return false
	//	}
	//	if numerator <= 0 || denominator <= 0 {
	//		acs.log.Errorf(unsupportedRuleErrorTemplate, policy.Rule)
	//		return false
	//	}
	//	return true
	//default:
	//	acs.log.Errorf(unsupportedRuleErrorTemplate, policy.Rule)
	//	return false
	//}

	return true
}

// 添加组织
func (acs *accessControlService) addOrg(orgId string, orgInfo interface{}) {
	_, loaded := acs.orgList.LoadOrStore(orgId, orgInfo)
	if loaded {
		acs.orgList.Store(orgId, orgInfo)
	} else {
		acs.orgNum++
	}
}

func (acs *accessControlService) getOrgInfoByOrgId(orgId string) interface{} {
	orgInfo, ok := acs.orgList.Load(orgId)
	if !ok {
		return nil
	}
	return orgInfo
}

// setVerifyOptionsFunc used to set verifyOptionsFunc which will check if  certificate chain valid
func (acs *accessControlService) setVerifyOptionsFunc(verifyOptionsFunc func() *bcx509.VerifyOptions) {
	acs.getCertVerifyOptions = verifyOptionsFunc
}

func (acs *accessControlService) createPrincipal(resourceName string, endorsements []*EndorsementEntry,
	message []byte) (Principal, error) {

	// 背书节点数量
	if len(endorsements) == 0 || message == nil {
		return nil, fmt.Errorf("setup access control principal failed, a principal should contain valid (non-empty)" +
			" signer information, signature, and message")
	}
	if endorsements[0] == nil {
		return nil, fmt.Errorf("setup access control principal failed, signer-signature pair should not be nil")
	}
	return &principal{
		resourceName: resourceName,
		endorsement:  endorsements,
		message:      message,
		targetOrg:    "",
	}, nil
}

// 在缓存中查找 member
func (acs *accessControlService) lookUpMemberInCache(memberInfo string) (*memberCached, bool) {
	ret, ok := acs.memberCache.Get(memberInfo)
	if ok {
		return ret.(*memberCached), true
	}
	return nil, false
}

func (acs *accessControlService) newCertMember(pbMember *Member) (MemberInterface, error) {
	return newCertMemberFromPb(pbMember, acs)
}

func newCertMemberFromPb(member *Member, acs *accessControlService) (*certificateMember, error) {

	if member.MemberType == MemberType_CERT {
		return newMemberFromCertPem(member.OrgId, acs.hashType, member.MemberInfo, false)
	}

	if member.MemberType == MemberType_CERT_HASH {
		return newMemberFromCertPem(member.OrgId, acs.hashType, member.MemberInfo, true)
	}

	if member.MemberType == MemberType_ALIAS {
		return newMemberFromCertPem(member.OrgId, acs.hashType, member.MemberInfo, false)
	}

	return nil, fmt.Errorf("setup member failed, unsupport cert member type")
}

func (acs *accessControlService) lookUpPolicyByResourceName(resourceName string) (*policy, error) {
	_, policyResourceName := getBlockVersionAndResourceName(resourceName)
	resourceName = policyResourceName

	if p, ok := acs.lastestPolicyMap.Load(resourceName); ok {
		return p.(*policy), nil
	}
	p, ok := acs.resourceNamePolicyMap.Load(resourceName)
	if !ok {
		if p, ok = acs.exceptionalPolicyMap.Load(resourceName); !ok {
			return nil, fmt.Errorf("look up access policy failed, did not configure access policy "+
				"for resource %s", resourceName)
		}
	}
	return p.(*policy), nil
}

// getBlockVersionAndResourceName return blockVersion and resourceName
func getBlockVersionAndResourceName(resourceNameWithPrefix string) (blockVersion uint32, resourceName string) {
	blockVersionAndResourceName := strings.Split(resourceNameWithPrefix, ":")
	if len(blockVersionAndResourceName) == 2 {
		version, err := strconv.ParseUint(blockVersionAndResourceName[0], 10, 32)
		if err != nil {
			blockVersion = 0
		}
		blockVersion = uint32(version)
		resourceName = blockVersionAndResourceName[1]
	} else if len(blockVersionAndResourceName) == 1 {
		resourceName = blockVersionAndResourceName[0]
	}

	return blockVersion, resourceName
}

func (acs *accessControlService) verifyPrincipalPolicy(principal, refinedPrincipal Principal, p *policy) (
	bool, error) {
	endorsements := refinedPrincipal.GetEndorsement()
	rule := p.GetRule()

	switch rule {
	case RuleForbidden:
		return false, fmt.Errorf("authentication fail: [%s] is forbidden to access", refinedPrincipal.GetResourceName())
	case RuleMajority:
		return acs.verifyPrincipalPolicyRuleMajorityCase(p, endorsements)
	case RuleSelf:
		return acs.verifyPrincipalPolicyRuleSelfCase(principal.GetTargetOrgId(), endorsements)
	case RuleAny:
		return acs.verifyPrincipalPolicyRuleAnyCase(p, endorsements, principal.GetResourceName())
	case RuleAll:
		return acs.verifyPrincipalPolicyRuleAllCase(p, endorsements)
	default:
		return acs.verifyPrincipalPolicyRuleDefaultCase(p, endorsements)
	}
}

func (acs *accessControlService) verifyPrincipalPolicyRuleMajorityCase(p *policy,
	endorsements []*EndorsementEntry) (bool, error) {
	// notice: accept admin role only, and require majority of all the organizations on the chain
	role := RoleAdmin
	// orgList, _ := buildOrgListRoleListOfPolicyForVerifyPrincipal(p)

	// warning: majority keywork with non admin constraints
	/*
		if roleList[0] != protocol.protocol.RoleAdmin {
			return false, fmt.Errorf("authentication fail: MAJORITY keyword only allows admin role")
		}
	*/

	numOfValid := acs.countValidEndorsements(map[string]bool{}, map[Role]bool{role: true}, endorsements)

	if float64(numOfValid) > float64(acs.orgNum)/2.0 {
		return true, nil
	}
	return false, fmt.Errorf("%s: %d valid endorsements required, %d valid endorsements received",
		notEnoughParticipantsSupportError, int(float64(acs.orgNum)/2.0+1), numOfValid)
}

func (acs *accessControlService) countValidEndorsements(orgList map[string]bool, roleList map[Role]bool,
	endorsements []*EndorsementEntry) int {
	refinedEndorsements := acs.getValidEndorsements(orgList, roleList, endorsements)
	return countOrgsFromEndorsements(refinedEndorsements)
}

func countOrgsFromEndorsements(endorsements []*EndorsementEntry) int {
	mapOrg := map[string]int{}
	for _, endorsement := range endorsements {
		mapOrg[endorsement.Signer.OrgId]++
	}
	return len(mapOrg)
}

func (acs *accessControlService) getValidEndorsements(orgList map[string]bool, roleList map[Role]bool,
	endorsements []*EndorsementEntry) []*EndorsementEntry {
	var refinedEndorsements []*EndorsementEntry
	for _, endorsement := range endorsements {
		if len(orgList) > 0 {
			if _, ok := orgList[endorsement.Signer.OrgId]; !ok {
				//acs.log.Debugf("authentication warning: signer's organization [%s] is not permitted, requires",
				//	endorsement.Signer.OrgId, orgList)
				continue
			}
		}

		if len(roleList) == 0 {
			refinedEndorsements = append(refinedEndorsements, endorsement)
			continue
		}

		member := acs.getMemberFromCache(endorsement.Signer)
		if member == nil {
			//acs.log.Debugf(
			//	"authentication warning: the member is not in member cache, memberInfo[%s]",
			//	string(endorsement.Signer.MemberInfo))
			continue
		}

		isRoleMatching := isRoleMatching(member.GetRole(), roleList, &refinedEndorsements, endorsement)
		if !isRoleMatching {
			//acs.log.Debugf(
			//	"authentication warning: signer's role [%v] is not permitted, requires [%v]",
			//	member.GetRole(),
			//	roleList,
			//)
		}
	}

	return refinedEndorsements
}

func isRoleMatching(signerRole Role, roleList map[Role]bool,
	refinedEndorsements *[]*EndorsementEntry, endorsement *EndorsementEntry) bool {
	isRoleMatching := false
	if _, ok := roleList[signerRole]; ok {
		*refinedEndorsements = append(*refinedEndorsements, endorsement)
		isRoleMatching = true
	}
	return isRoleMatching
}

// 尝试从缓存中获取成员信息，并根据需要进行验证和更新。
// 如果成员信息不在缓存中或缓存中的信息不一致，则尝试创建新的成员信息
func (acs *accessControlService) getMemberFromCache(member *Member) MemberInterface {
	// 根据成员的信息从缓存中查找对应的成员
	cached, ok := acs.lookUpMemberInCache(string(member.MemberInfo))
	if ok {
		//acs.log.Debugf("member found in local cache")
		// 如果找到了成员（ok为true），并且缓存中的成员的组织ID与请求中的成员组织ID不匹配，
		// 则记录一条调试日志并返回nil，表示缓存中的成员信息与请求的成员信息不一致。
		if cached.member.GetOrgId() != member.OrgId {
			//acs.log.Debugf("get member from cache failed: member orgId does not match on chain")
			return nil
		}
		return cached.member
	}

	//handle false positive when member cache is cleared
	var tmpMember MemberInterface
	var err error
	var certChains [][]*bcx509.Certificate

	// 如果是基于证书的权限模式
	if acs.authType == PermissionedWithCert {
		// 创建一个新的证书成员（certificateMember），并对其证书进行验证
		tmpMember, err = acs.newCertMember(member)
		certMember, ok := tmpMember.(*certificateMember)
		if !ok {
			return nil
		}
		certChains, err = certMember.cert.Verify(*acs.getCertVerifyOptions())
		if err != nil {
			//acs.log.Debugf("certMember verify cert chain failed, err = %s", err.Error())
			return nil
		}
		if len(certChains) == 0 {
			//acs.log.Debugf("certMember verify cert chain failed, len(certChains) = %d", len(certChains))
			return nil
		}
	}
	//} else if acs.authType == protocol.PermissionedWithKey { // 如果是基于公钥的权限模式
	//	// 调用acs.pwkNewMember创建一个新的成员
	//	tmpMember, err = acs.pwkNewMember(member)
	//}
	if err != nil {
		//acs.log.Debugf("new member failed, authType = %s, err = %s", acs.authType, err.Error())
		return nil
	}

	//add to cache
	// 添加到缓存中
	if certChains != nil {
		cached = &memberCached{
			member:    tmpMember,
			certChain: certChains[0],
		}
	} else {
		cached = &memberCached{
			member:    tmpMember,
			certChain: nil,
		}
	}
	acs.addMemberToCache(string(member.MemberInfo), cached)

	return tmpMember
}

// 添加 member 到缓存中
func (acs *accessControlService) addMemberToCache(memberInfo string, member *memberCached) {
	acs.memberCache.Add(memberInfo, member)
}

func (acs *accessControlService) verifyPrincipalPolicyRuleSelfCase(targetOrg string,
	endorsements []*EndorsementEntry) (bool, error) {
	role := RoleAdmin
	if targetOrg == "" {
		return false, fmt.Errorf("authentication fail: SELF keyword requires the owner of the affected target")
	}
	for _, entry := range endorsements {
		if entry.Signer.OrgId != targetOrg {
			continue
		}

		member := acs.getMemberFromCache(entry.Signer)
		if member == nil {
			//acs.log.Debugf(
			//	"authentication warning: the member is not in member cache, memberInfo[%s]",
			//	string(entry.Signer.MemberInfo))
			continue
		}

		if member.GetRole() == role {
			return true, nil
		}
	}
	return false, fmt.Errorf("authentication fail: target [%s] does not belong to the signer", targetOrg)
}

func (acs *accessControlService) verifyPrincipalPolicyRuleAnyCase(p *policy, endorsements []*EndorsementEntry,
	resourceName string) (bool, error) {
	orgList, roleList := buildOrgListRoleListOfPolicyForVerifyPrincipal(p)
	for _, endorsement := range endorsements {
		if len(orgList) > 0 {
			if _, ok := orgList[endorsement.Signer.OrgId]; !ok {
				//acs.log.Debugf("authentication warning: signer's organization [%s] is not permitted, requires [%v]",
				//	endorsement.Signer.OrgId, p.GetOrgList())
				continue
			}
		}

		if len(roleList) == 0 {
			return true, nil
		}

		member := acs.getMemberFromCache(endorsement.Signer)
		if member == nil {
			//acs.log.Debugf(
			//	"authentication warning: the member is not in member cache, memberInfo[%s]",
			//	string(endorsement.Signer.MemberInfo))
			continue
		}

		if _, ok := roleList[member.GetRole()]; ok {
			return true, nil
		}
		//acs.log.Debugf("authentication warning: signer's role [%v] is not permitted, requires [%v]",
		//	member.GetRole(), p.GetRoleList())
	}

	return false, fmt.Errorf("authentication fail: signers do not meet the requirement (%s)",
		resourceName)
}

func buildOrgListRoleListOfPolicyForVerifyPrincipal(p *policy) (map[string]bool, map[Role]bool) {
	orgListRaw := p.GetOrgList()
	roleListRaw := p.GetRoleList()
	orgList := map[string]bool{}
	roleList := map[Role]bool{}
	for _, orgRaw := range orgListRaw {
		orgList[orgRaw] = true
	}
	for _, roleRaw := range roleListRaw {
		roleList[roleRaw] = true
	}
	return orgList, roleList
}

func (acs *accessControlService) verifyPrincipalPolicyRuleAllCase(p *policy, endorsements []*EndorsementEntry) (
	bool, error) {
	orgList, roleList := buildOrgListRoleListOfPolicyForVerifyPrincipal(p)
	numOfValid := acs.countValidEndorsements(orgList, roleList, endorsements)
	if len(orgList) <= 0 && numOfValid == int(atomic.LoadInt32(&acs.orgNum)) {
		return true, nil
	}
	if len(orgList) > 0 && numOfValid == len(orgList) {
		return true, nil
	}
	return false, fmt.Errorf("authentication fail: not all of the listed organtizations consend to this action")
}

func (acs *accessControlService) verifyPrincipalPolicyRuleDefaultCase(p *policy,
	endorsements []*EndorsementEntry) (bool, error) {
	rule := p.GetRule()
	orgList, roleList := buildOrgListRoleListOfPolicyForVerifyPrincipal(p)
	nums := strings.Split(string(rule), LIMIT_DELIMITER)
	switch len(nums) {
	case 1:
		threshold, err := strconv.Atoi(nums[0])
		if err != nil {
			return false, fmt.Errorf("authentication fail: unrecognized rule, should be ANY, MAJORITY, ALL, " +
				"SELF, ac threshold (integer), or ac portion (fraction)")
		}

		numOfValid := acs.countValidEndorsements(orgList, roleList, endorsements)
		if numOfValid >= threshold {
			return true, nil
		}
		return false, fmt.Errorf("%s: %d valid endorsements required, %d valid endorsements received",
			notEnoughParticipantsSupportError, threshold, numOfValid)

	case 2:
		numerator, err := strconv.Atoi(nums[0])
		denominator, err2 := strconv.Atoi(nums[1])
		if err != nil || err2 != nil {
			return false, fmt.Errorf("authentication fail: unrecognized rule, should be ANY, MAJORITY, ALL, " +
				"SELF, an integer, or ac fraction")
		}

		if denominator <= 0 {
			denominator = int(atomic.LoadInt32(&acs.orgNum))
		}

		numOfValid := acs.countValidEndorsements(orgList, roleList, endorsements)

		var numRequired float64
		if len(orgList) <= 0 {
			numRequired = float64(atomic.LoadInt32(&acs.orgNum)) * float64(numerator) / float64(denominator)
		} else {
			numRequired = float64(len(orgList)) * float64(numerator) / float64(denominator)
		}
		if float64(numOfValid) >= numRequired {
			return true, nil
		}
		return false, fmt.Errorf("%s: %f valid endorsements required, %d valid endorsements received",
			notEnoughParticipantsSupportError, numRequired, numOfValid)
	default:
		return false, fmt.Errorf("authentication fail: unrecognized principle type, should be ANY, MAJORITY, " +
			"ALL, SELF, an integer (Threshold), or ac fraction (Portion)")
	}
}

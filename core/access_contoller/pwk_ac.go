package access_contoller

import (
	"crypto"
	"fmt"
	"sync"
	"sync/atomic"
)

type PWKACProvider struct {
	acService *accessControlService

	// local org id
	localOrg string

	// admin list in permissioned public key mode
	adminMember *sync.Map

	// consensus list in permissioned public key mode
	consensusMember *sync.Map
}

type adminMemberModel struct {
	publicKey crypto.PublicKey
	pkBytes   []byte
	orgId     string
}

type consensusMemberModel struct {
	nodeId string
	orgId  string
}

// VerifyPrincipal verifies if the principal for the resource is met
// 验证给定的 principal 是否满足对应资源的访问控制策略
func (pp *PWKACProvider) VerifyPrincipal(principal Principal) (bool, error) {
	// 安全地读取orgNum的值
	// 它表示链上的组织或信任节点数量。如
	// 果这个数量小于或等于0，则表示链上没有配置组织或信任节点，因此认证失败，并返回相应的错误信息
	if atomic.LoadInt32(&pp.acService.orgNum) <= 0 {
		return false, fmt.Errorf("authentication failed: empty organization list or trusted node list on this chain")
	}

	// 处理和优化传入的principal对象
	refinedPrincipal, err := pp.refinePrincipal(principal)
	if err != nil {
		return false, fmt.Errorf("authentication failed, [%s]", err.Error())
	}

	// 检查配置中的IsSkipAccessControl标志是否为真，如果为真，则跳过访问控制检查。
	// 这通常用于调试或测试环境，以便开发者不需要配置完整的访问控制策略即可测试功能
	//if localconf.ChainMakerConfig.DebugConfig.IsSkipAccessControl {
	//	return true, nil
	//}

	// 查找对应的访问控制策略。如果无法找到策略或出现其他错误，则认证失败，并返回错误
	p, err := pp.acService.lookUpPolicyByResourceName(principal.GetResourceName())
	if err != nil {
		return false, fmt.Errorf("authentication failed, [%s]", err.Error())
	}

	// 调用verifyPrincipalPolicy方法，传入原始的principal对象、处理后的principal对象和找到的策略对象，
	// 以验证principal是否满足该策略。根据验证结果返回相应的布尔值和可能的错误
	return pp.acService.verifyPrincipalPolicy(principal, refinedPrincipal, p)
}

// all-in-one validation for signing members: certificate chain/whitelist, signature, policies
// 对传入的 principal 进行一系列验证和细化处理，以确保背书、消息和相关策略都符合安全要求
// 一个全面的验证流程，确保了背书的合法性和消息的完整性
func (pp *PWKACProvider) refinePrincipal(principal Principal) (Principal, error) {
	// 提取背书和验证的签名消息
	endorsements := principal.GetEndorsement()
	msg := principal.GetMessage()

	// 对背书进行验证和筛选
	// 返回经过验证和筛选的背书列表refinedEndorsement
	refinedEndorsement := pp.RefineEndorsements(endorsements, msg)
	// 如果refinedEndorsement的长度小于或等于0，说明没有任何背书通过验证，因此返回错误信息。
	if len(refinedEndorsement) <= 0 {
		return nil, fmt.Errorf("refine endorsements failed, all endorsers have failed verification")
	}

	// 创建一个细化后的principal对象
	refinedPrincipal, err := pp.CreatePrincipal(principal.GetResourceName(), refinedEndorsement, msg)
	if err != nil {
		return nil, fmt.Errorf("create principal failed: [%s]", err.Error())
	}

	return refinedPrincipal, nil
}

// 验证并筛选一组背书，确保它们来自有效且被信任的成员
// 通过对背书条目的签名进行验证，确保每个背书都来自一个有效的签名者
func (pp *PWKACProvider) RefineEndorsements(endorsements []*EndorsementEntry,
	msg []byte) []*EndorsementEntry {

	refinedSigners := map[string]bool{}
	var refinedEndorsement []*EndorsementEntry

	for _, endorsementEntry := range endorsements {
		// 对于每一个背书条目，函数会创建一个新的背书对象，并复制原始背书的相关信息
		endorsement := &EndorsementEntry{
			Signer: &Member{
				OrgId:      endorsementEntry.Signer.OrgId,
				MemberInfo: endorsementEntry.Signer.MemberInfo,
				MemberType: endorsementEntry.Signer.MemberType,
			},
			Signature: endorsementEntry.Signature,
		}

		// 将签名者的成员信息转换为字符串，以便后续处理
		memInfo := string(endorsement.Signer.MemberInfo)

		// 根据签名者信息创建一个成员对象，用于验证签名
		remoteMember, err := pp.NewMember(endorsement.Signer)
		if err != nil {
			//pp.acService.log.Infof("new member failed: [%s]", err.Error())
			continue
		}

		// 使用成员的 Verify 方法验证签名是否有效
		if err := remoteMember.Verify(pp.GetHashAlg(), msg, endorsement.Signature); err != nil {
			//pp.acService.log.Infof("signer member verify signature failed: [%s]", err.Error())
			//pp.acService.log.Debugf("information for invalid signature:\norganization: %s\npubkey: %s\nmessage: %s\n"+
			//	"signature: %s", endorsement.Signer.OrgId, memInfo, hex.Dump(msg), hex.Dump(endorsement.Signature))
			continue
		}

		// 检查签名者是否已经被处理过，防止重复添加
		if _, ok := refinedSigners[memInfo]; !ok {
			// 如果该签名者未被处理过，则将其标记为已处理，并将相应的背书条目添加到结果列表中
			refinedSigners[memInfo] = true
			refinedEndorsement = append(refinedEndorsement, endorsement)
		}
	}
	return refinedEndorsement
}

// NewMember creates a member from pb Member
func (pp *PWKACProvider) NewMember(member *Member) (MemberInterface, error) {
	return pp.acService.newPkMember(member, pp.adminMember, pp.consensusMember)
}

// 基于给定的成员信息创建一个新的公钥成员对象
func (acs *accessControlService) newPkMember(member *Member, adminList,
	consensusList *sync.Map) (MemberInterface, error) {

	// 尝试从缓存中获取成员对象
	memberCache := acs.getMemberFromCache(member)
	if memberCache != nil {
		return memberCache, nil
	}

	// 调用newPkMemberFromAcs函数根据提供的成员信息、管理员列表和共识列表以及访问控制服务对象创建一个新的公钥成员对象
	pkMember, err := newPkMemberFromAcs(member, adminList, consensusList, acs)
	if err != nil {
		return nil, fmt.Errorf("new public key member failed: %s", err.Error())
	}

	// 对新创建的公钥成员进行验证，确保其组织ID与提供的成员信息中的组织ID相匹配。如果不匹配，返回错误信息
	if pkMember.GetOrgId() != member.OrgId && member.OrgId != "" {
		return nil, fmt.Errorf("new public key member failed: member orgId does not match on chain")
	}

	// 加入缓存
	cached := &memberCached{
		member:    pkMember,
		certChain: nil,
	}
	acs.addMemberToCache(string(member.MemberInfo), cached)
	return pkMember, nil
}

// CreatePrincipal creates a principal for one time authentication
func (pp *PWKACProvider) CreatePrincipal(resourceName string, endorsements []*EndorsementEntry,
	message []byte) (Principal, error) {
	return pp.acService.createPrincipal(resourceName, endorsements, message)
}

// GetHashAlg return hash algorithm the access control provider uses
func (pp *PWKACProvider) GetHashAlg() string {
	return pp.acService.hashType
}

package access_contoller

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	bcx509 "my_simplechain/core/access_contoller/crypto/x509"
	"my_simplechain/core/access_contoller/my_lru"
	"my_simplechain/params"
	"sync"
	"sync/atomic"
)

// 这个结构体的目的是提供对证书和访问控制相关数据的管理和操作，
// 包括证书缓存、吊销列表、冻结列表、组织成员验证选项、本地组织信息、第三方信任的成员列表以及共识类型等
type certACProvider struct {
	// 一个指向 accessControlService 类型的指针，用于执行访问控制服务
	acService *accessControlService

	// local cache for certificates (reduce the size of block)
	// 并发安全的 LRU 缓存，用于存储证书，减少区块的大小
	certCache *my_lru.Cache

	// local cache for certificate revocation list and frozen list
	// crl 和 frozenList 是两个同步映射，分别用于存储证书吊销列表和冻结列表
	crl        sync.Map
	frozenList sync.Map

	// verification options for organization members
	// opts 是用于组织成员验证选项的 bcx509.VerifyOptions 结构
	opts bcx509.VerifyOptions

	// 一个指向 organization 结构的指针，表示本地组织
	localOrg *organization

	//third-party trusted members
	// trustMembers 是一个同步映射，用于存储第三方信任的成员
	trustMembers *sync.Map

	// store 是一个接口类型，用于访问区块链存储
	//store protocol.BlockchainStore

	//consensus type
	// consensusType 是一个枚举类型 consensus.ConsensusType，表示共识类型
	//consensusType consensus.ConsensusType
}

func NewACProvider(chainConfig *params.ChainConfig, localOrgId string) (*certACProvider, error) {

	// 构建一个完整的访问控制提供者实例
	//certACProvider, err := newCertACProvider(chainConf.ChainConfig(), localOrgId, store, log)
	certACProvider, err := newCertACProvider(chainConfig, localOrgId)
	if err != nil {
		return nil, err
	}

	//msgBus.Register(msgbus.ChainConfig, certACProvider)
	//msgBus.Register(msgbus.CertManageCertsDelete, certACProvider)
	//msgBus.Register(msgbus.CertManageCertsUnfreeze, certACProvider)
	//msgBus.Register(msgbus.CertManageCertsFreeze, certACProvider)
	//msgBus.Register(msgbus.CertManageCertsRevoke, certACProvider)
	//msgBus.Register(msgbus.CertManageCertsAliasDelete, certACProvider)
	//msgBus.Register(msgbus.CertManageCertsAliasUpdate, certACProvider)
	//msgBus.Register(msgbus.MaxbftEpochConf, certACProvider)

	//v220_compat Deprecated
	//chainConf.AddWatch(certACProvider)   //nolint: staticcheck
	//chainConf.AddVmWatch(certACProvider) //nolint: staticcheck
	return certACProvider, nil
}

// 这个构造函数负责初始化 certACProvider 实例的各个字段，
// 并根据链配置中的共识类型来加载相应的配置信息，从而构建一个完整的访问控制提供者实例
func newCertACProvider(chainConfig *params.ChainConfig, localOrgId string) (*certACProvider, error) {

	//cache, err2 := my_lru.New(10)

	// 创建一个 certACProvider, 初始化各个字段
	certACProvider := &certACProvider{
		// 初始化为一个并发安全的 LRU 缓存
		//certCache: concurrentlru.New(localconf.ChainMakerConfig.NodeConfig.CertCacheSize),

		// 初始化为 sync.Map 类型的空映射
		crl:        sync.Map{},
		frozenList: sync.Map{},

		// 初始化为包含根证书和中间证书的 bcx509.VerifyOptions 结构
		//opts: bcx509.VerifyOptions{
		//	Intermediates: bcx509.NewCertPool(),
		//	Roots:         bcx509.NewCertPool(),
		//},

		// 初始化为 nil
		//localOrg: nil,

		//  初始化为一个空的 sync.Map
		trustMembers: &sync.Map{},

		// 被设置为传入的区块链存储
		//store: store,
	}

	//var maxbftCfg *maxbft.GovernanceContract
	var err error

	// 被设置为传入的链配置中的共识类型
	//certACProvider.consensusType = chainConfig.Consensus.Type

	// 如果链配置的共识类型为 MAXBFT，则加载 MAXBFT 配置，并更新 chainConfig 为 MAXBFT 配置的链配置。
	// 这一步是为了兼容 MAXBFT 合约可能对链配置的修改。
	//if certACProvider.consensusType == consensus.ConsensusType_MAXBFT {
	// 从治理合约中加载链配置
	//maxbftCfg, err = certACProvider.loadChainConfigFromGovernance()
	//if err != nil {
	//	return nil, err
	//}
	//omit 1'st epoch, GovernanceContract don't save chainConfig in 1'st epoch
	//if maxbftCfg != nil && maxbftCfg.ChainConfig != nil {
	//	chainConfig = maxbftCfg.ChainConfig
	//}
	//}
	//log.DebugDynamic(func() string {
	//	return fmt.Sprintf("init ac from chainconfig: %+v", chainConfig)
	//})

	// 初始化信任成员列表
	err = certACProvider.initTrustMembers(chainConfig.TrustMembers)
	if err != nil {
		return nil, err
	}

	// 初始化访问控制服务 (acService)，
	// 并设置验证选项函数为 certACProvider 的 getVerifyOptions 方法
	certACProvider.acService = initAccessControlService()
	certACProvider.acService.setVerifyOptionsFunc(certACProvider.getVerifyOptions)

	// 初始化信任根证书列表
	err = certACProvider.initTrustRoots(chainConfig.TrustRoots, localOrgId)
	if err != nil {
		return nil, err
	}

	// 初始化资源策略
	certACProvider.acService.initResourcePolicy(chainConfig.ResourcePolicies, localOrgId)
	certACProvider.opts.KeyUsages = make([]x509.ExtKeyUsage, 1)
	certACProvider.opts.KeyUsages[0] = x509.ExtKeyUsageAny

	// 根据共识类型的不同，更新证书冻结列表和证书吊销列表。
	// 如果是 MAXBFT 共识类型，则从 MAXBFT 配置中获取更新；否则，从区块链存储中加载已有的列表
	//if certACProvider.consensusType == consensus.ConsensusType_MAXBFT && maxbftCfg != nil {
	//	err = certACProvider.updateFrozenAndCRL(maxbftCfg)
	//	if err != nil {
	//		return nil, err
	//	}
	//} else {
	//	if err := certACProvider.loadCRL(); err != nil {
	//		return nil, err
	//	}
	//	if err := certACProvider.loadCertFrozenList(); err != nil {
	//		return nil, err
	//	}
	//}

	// 返回创建的 certACProvider 实例
	return certACProvider, nil
}

func (cp *certACProvider) initTrustMembers(trustMembers []*params.TrustMemberConfig) error {
	var syncMap sync.Map
	for _, member := range trustMembers {
		certBlock, _ := pem.Decode([]byte(member.MemberInfo))
		if certBlock == nil {
			return fmt.Errorf("init trust members failed, none certificate given, memberInfo:[%s]",
				member.MemberInfo)
		}
		trustMemberCert, err := bcx509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("init trust members failed, parse certificate failed, memberInfo:[%s]",
				member.MemberInfo)
		}
		cached := &trustMemberCached{
			trustMember: member,
			cert:        trustMemberCert,
		}
		syncMap.Store(member.MemberInfo, cached)
	}
	cp.trustMembers = &syncMap

	return nil
}

// 该函数主要用于初始化证书认证提供程序的信任根证书和中级证书，并将其添加到证书池中
func (cp *certACProvider) initTrustRoots(roots []*params.TrustRootConfig, localOrgId string) error {
	// 遍历所有信任根证书配置
	for _, orgRoot := range roots {
		// 为每个组织创建一个组织结构体
		org := &organization{
			id: orgRoot.OrgId,
			//trustedRootCerts:         map[string]*bcx509.Certificate{},
			//trustedIntermediateCerts: map[string]*bcx509.Certificate{},
			trustedRootCerts:         map[string]*bcx509.Certificate{},
			trustedIntermediateCerts: map[string]*bcx509.Certificate{},
		}

		for _, root := range orgRoot.Roots {
			// 构建证书链
			certificateChain, err := cp.buildCertificateChain(root, orgRoot.OrgId, org)
			if err != nil {
				return err
			}
			// 如果证书链最后为空，或最后一个证书不是 CA 证书，则返回错误
			if certificateChain == nil || !certificateChain[len(certificateChain)-1].IsCA {
				return fmt.Errorf("the certificate configured as root for organization %s is not a CA certificate", orgRoot.OrgId)
			}
			// 将根证书添加到组织的根信任证书映射和证书池中
			org.trustedRootCerts[string(certificateChain[len(certificateChain)-1].Raw)] =
				certificateChain[len(certificateChain)-1]
			cp.opts.Roots.AddCert(certificateChain[len(certificateChain)-1])
			// 将中级证书添加到组织的信任中级证书映射和证书池中
			for i := 0; i < len(certificateChain); i++ {
				org.trustedIntermediateCerts[string(certificateChain[i].Raw)] = certificateChain[i]
				cp.opts.Intermediates.AddCert(certificateChain[i])
			}

			/*for _, certificate := range certificateChain {
				if certificate.IsCA {
					org.trustedRootCerts[string(certificate.Raw)] = certificate
					ac.opts.Roots.AddCert(certificate)
				} else {
					org.trustedIntermediateCerts[string(certificate.Raw)] = certificate
					ac.opts.Intermediates.AddCert(certificate)
				}
			}*/

			if len(org.trustedRootCerts) <= 0 {
				return fmt.Errorf(
					"setup organization failed, no trusted root (for %s): "+
						"please configure trusted root certificate or trusted public key whitelist",
					orgRoot.OrgId,
				)
			}
		}
		// 将组织添加到认证服务中
		cp.acService.addOrg(orgRoot.OrgId, org)
	}

	// 获取本地组织信息
	localOrg := cp.acService.getOrgInfoByOrgId(localOrgId)
	// 如果本地组织不存在，则创建一个新的组织结构体
	if localOrg == nil {
		localOrg = &organization{
			id:                       localOrgId,
			trustedRootCerts:         map[string]*bcx509.Certificate{},
			trustedIntermediateCerts: map[string]*bcx509.Certificate{},
		}
	}
	// 将本地组织信息添加到证书认证提供程序中
	cp.localOrg, _ = localOrg.(*organization)
	return nil
}

func (cp *certACProvider) buildCertificateChain(root, orgId string, org *organization) ([]*bcx509.Certificate, error) {
	var certificates, certificateChain []*bcx509.Certificate
	pemBlock, rest := pem.Decode([]byte(root))
	for pemBlock != nil {
		cert, errCert := bcx509.ParseCertificate(pemBlock.Bytes)
		if errCert != nil || cert == nil {
			return nil, fmt.Errorf("invalid entry int trusted root cert list")
		}
		if len(cert.Signature) == 0 {
			return nil, fmt.Errorf("invalid certificate [SN: %s]", cert.SerialNumber)
		}
		certificates = append(certificates, cert)
		pemBlock, rest = pem.Decode(rest)
	}
	certificateChain = bcx509.BuildCertificateChain(certificates)
	return certificateChain, nil
}

func (cp *certACProvider) loadCRL() error {
	//if cp.acService.dataStore == nil {
	//	return nil
	//}
	//
	//crlAKIList, err := cp.acService.dataStore.ReadObject(syscontract.SystemContract_CERT_MANAGE.String(),
	//	[]byte(protocol.CertRevokeKey))
	//if err != nil {
	//	return fmt.Errorf("fail to update CRL list: %v", err)
	//}
	//if crlAKIList == nil {
	//	cp.acService.log.Debugf("empty CRL")
	//	return nil
	//}
	//
	//var crlAKIs []string
	//err = json.Unmarshal(crlAKIList, &crlAKIs)
	//if err != nil {
	//	return fmt.Errorf("fail to update CRL list: %v", err)
	//}
	//
	//err = cp.storeCrls(crlAKIs)
	//return err

	return errors.New("")
}

func (cp *certACProvider) getVerifyOptions() *bcx509.VerifyOptions {
	return &cp.opts
}

// CreatePrincipal creates a principal for one time authentication
func (cp *certACProvider) CreatePrincipal(resourceName string, endorsements []*EndorsementEntry,
	message []byte) (Principal, error) {
	return cp.acService.createPrincipal(resourceName, endorsements, message)
}

// VerifyPrincipal verifies if the principal for the resource is met
func (cp *certACProvider) VerifyPrincipal(principal Principal) (bool, error) {

	if atomic.LoadInt32(&cp.acService.orgNum) <= 0 {
		return false, fmt.Errorf("authentication failed: empty organization list or trusted node list on this chain")
	}

	refinedPrincipal, err := cp.refinePrincipal(principal)
	if err != nil {
		return false, fmt.Errorf("authentication failed, [%s]", err.Error())
	}

	//if localconf.ChainMakerConfig.DebugConfig.IsSkipAccessControl {
	//	return true, nil
	//}

	p, err := cp.acService.lookUpPolicyByResourceName(principal.GetResourceName())
	if err != nil {
		return false, fmt.Errorf("authentication failed, [%s]", err.Error())
	}

	return cp.acService.verifyPrincipalPolicy(principal, refinedPrincipal, p)
}

// all-in-one validation for signing members: certificate chain/whitelist, signature, policies
func (cp *certACProvider) refinePrincipal(principal Principal) (Principal, error) {
	endorsements := principal.GetEndorsement()
	msg := principal.GetMessage()
	refinedEndorsement := cp.RefineEndorsements(endorsements, msg)
	if len(refinedEndorsement) <= 0 {
		return nil, fmt.Errorf("refine endorsements failed, all endorsers have failed verification")
	}

	refinedPrincipal, err := cp.CreatePrincipal(principal.GetResourceName(), refinedEndorsement, msg)
	if err != nil {
		return nil, fmt.Errorf("create principal failed: [%s]", err.Error())
	}

	return refinedPrincipal, nil
}

func (cp *certACProvider) RefineEndorsements(endorsements []*EndorsementEntry,
	msg []byte) []*EndorsementEntry {

	refinedSigners := map[string]bool{}
	var refinedEndorsement []*EndorsementEntry
	var memInfo string

	for _, endorsementEntry := range endorsements {
		endorsement := &EndorsementEntry{
			Signer: &Member{
				OrgId:      endorsementEntry.Signer.OrgId,
				MemberInfo: endorsementEntry.Signer.MemberInfo,
				MemberType: endorsementEntry.Signer.MemberType,
			},
			Signature: endorsementEntry.Signature,
		}
		if endorsement.Signer.MemberType == MemberType_CERT {
			//cp.acService.log.Debugf("target endorser uses full certificate")
			memInfo = string(endorsement.Signer.MemberInfo)
		}
		if endorsement.Signer.MemberType == MemberType_CERT_HASH ||
			endorsement.Signer.MemberType == MemberType_ALIAS {
			//cp.acService.log.Debugf("target endorser uses compressed certificate")
			memInfoBytes, ok := cp.lookUpCertCache(endorsement.Signer.MemberInfo)
			if !ok {
				//cp.acService.log.Warnf("authentication failed, unknown signer, the provided certificate ID is not registered")
				continue
			}
			memInfo = string(memInfoBytes)
			endorsement.Signer.MemberInfo = memInfoBytes
		}

		signerInfo, ok := cp.acService.lookUpMemberInCache(memInfo)
		if !ok {
			//cp.acService.log.Debugf("certificate not in local cache, should verify it against the trusted root certificates: "+
			//	"\n%s", memInfo)
			remoteMember, certChain, ok, err := cp.verifyPrincipalSignerNotInCache(endorsement, msg, memInfo)
			if !ok {
				//cp.acService.log.Warnf("verify principal signer not in cache failed, [endorsement: %v],[err: %s]",
				//	endorsement, err.Error())
				fmt.Println(err)
				continue
			}

			signerInfo = &memberCached{
				member:    remoteMember,
				certChain: certChain,
			}
			cp.acService.addMemberToCache(memInfo, signerInfo)
		} else {
			flat, err := cp.verifyPrincipalSignerInCache(signerInfo, endorsement, msg, memInfo)
			if !flat {
				fmt.Println(err)
				//cp.acService.log.Warnf("verify principal signer in cache failed, [endorsement: %v],[err: %s]",
				//	endorsement, err.Error())
				continue
			}
		}

		if _, ok := refinedSigners[memInfo]; !ok {
			refinedSigners[memInfo] = true
			refinedEndorsement = append(refinedEndorsement, endorsement)
		}
	}
	return refinedEndorsement
}

// lookUpCertCache Cache for compressed certificate
func (cp *certACProvider) lookUpCertCache(certId []byte) ([]byte, bool) {
	ret, ok := cp.certCache.Get(string(certId))
	if !ok {
		////cp.acService.log.Debugf("looking up the full certificate for the compressed one [%v]", certId)
		//if cp.acService.dataStore == nil {
		//	cp.acService.log.Errorf("local data storage is not set up")
		//	return nil, false
		//}
		//certIdHex := hex.EncodeToString(certId)
		//cert, err := cp.acService.dataStore.ReadObject(syscontract.SystemContract_CERT_MANAGE.String(), []byte(certIdHex))
		//if err != nil {
		//	cp.acService.log.Errorf("fail to load compressed certificate from local storage [%s]", certIdHex)
		//	return nil, false
		//}
		//if cert == nil {
		//	cp.acService.log.Warnf("cert id [%s] does not exist in local storage", certIdHex)
		//	return nil, false
		//}
		//cp.addCertCache(string(certId), cert)
		//cp.acService.log.Debugf("compressed certificate [%s] found and stored in cache", certIdHex)
		//return cert, true
	} else if ret != nil {
		//cp.acService.log.Debugf("compressed certificate [%v] found in cache", []byte(certId))
		return ret.([]byte), true
	} else {
		//cp.acService.log.Debugf("fail to look up compressed certificate [%v] due to an internal error of local cache",
		//	[]byte(certId))
		return nil, false
	}

	return nil, true
}

func (cp *certACProvider) verifyPrincipalSignerNotInCache(endorsement *EndorsementEntry, msg []byte,
	memInfo string) (remoteMember MemberInterface, certChain []*bcx509.Certificate, ok bool, err error) {
	var isTrustMember bool
	remoteMember, isTrustMember, err = cp.newNoCacheMember(endorsement.Signer)
	if err != nil {
		err = fmt.Errorf("new member failed: [%s]", err.Error())
		ok = false
		return
	}

	if !isTrustMember {
		certChain, err = cp.verifyMember(remoteMember)
		if err != nil {
			err = fmt.Errorf("verify member failed: [%s]", err.Error())
			ok = false
			return
		}
	}

	if err = remoteMember.Verify(cp.acService.hashType, msg, endorsement.Signature); err != nil {
		err = fmt.Errorf("member verify signature failed: [%s]", err.Error())
		//cp.acService.log.Warnf("information for invalid signature:\norganization: %s\ncertificate: %s\nmessage: %s\n"+
		//	"signature: %s", endorsement.Signer.OrgId, memInfo, hex.Dump(msg), hex.Dump(endorsement.Signature))
		ok = false
		return
	}
	ok = true
	return
}

func (cp *certACProvider) newNoCacheMember(pbMember *Member) (member MemberInterface,
	isTrustMember bool, err error) {
	cached, ok := cp.loadTrustMembers(string(pbMember.MemberInfo))
	if ok {
		var isCompressed bool
		if pbMember.MemberType == MemberType_CERT {
			isCompressed = false
		}
		var certMember *certificateMember
		certMember, err = newCertMemberFromParam(cached.trustMember.OrgId, cached.trustMember.Role,
			cp.acService.hashType, isCompressed, []byte(cached.trustMember.MemberInfo))
		if err != nil {
			return nil, isTrustMember, err
		}
		isTrustMember = true
		return certMember, isTrustMember, nil
	}

	member, err = cp.acService.newCertMember(pbMember)
	if err != nil {
		return nil, isTrustMember, fmt.Errorf("new member failed: %s", err.Error())
	}
	return member, isTrustMember, nil
}

func (cp *certACProvider) loadTrustMembers(memberInfo string) (*trustMemberCached, bool) {
	cached, ok := cp.trustMembers.Load(string(memberInfo))
	if ok {
		return cached.(*trustMemberCached), ok
	}
	return nil, ok
}

func (cp *certACProvider) verifyPrincipalSignerInCache(signerInfo *memberCached, endorsement *EndorsementEntry,
	msg []byte, memInfo string) (bool, error) {
	// check CRL and certificate frozen list

	_, isTrustMember := cp.loadTrustMembers(memInfo)

	if !isTrustMember {
		err := cp.checkCRL(signerInfo.certChain)
		if err != nil {
			return false, fmt.Errorf("check CRL, error: [%s]", err.Error())
		}
		err = cp.checkCertFrozenList(signerInfo.certChain)
		if err != nil {
			return false, fmt.Errorf("check cert forzen list, error: [%s]", err.Error())
		}
		//cp.acService.log.Debugf("certificate is already seen, no need to verify against the trusted root certificates")

		if endorsement.Signer.OrgId != signerInfo.member.GetOrgId() {
			err := fmt.Errorf("authentication failed, signer does not belong to the organization it claims "+
				"[claim: %s, root cert: %s]", endorsement.Signer.OrgId, signerInfo.member.GetOrgId())
			return false, err
		}
	}
	if err := signerInfo.member.Verify(cp.acService.hashType, msg, endorsement.Signature); err != nil {
		err = fmt.Errorf("signer member verify signature failed: [%s]", err.Error())
		//cp.acService.log.Warnf("information for invalid signature:\norganization: %s\ncertificate: %s\nmessage: %s\n"+
		//	"signature: %s", endorsement.Signer.OrgId, memInfo, hex.Dump(msg), hex.Dump(endorsement.Signature))
		return false, err
	}
	return true, nil
}

func (cp *certACProvider) checkCRL(certChain []*bcx509.Certificate) error {
	if len(certChain) < 1 {
		return fmt.Errorf("given certificate chain is empty")
	}

	for _, cert := range certChain {
		akiCert := cert.AuthorityKeyId

		crl, ok := cp.crl.Load(string(akiCert))
		if ok {
			// we have ac CRL, check whether the serial number is revoked
			for _, rc := range crl.(*pkix.CertificateList).TBSCertList.RevokedCertificates {
				if rc.SerialNumber.Cmp(cert.SerialNumber) == 0 {
					return errors.New("certificate is revoked")
				}
			}
		}
	}

	return nil
}

func (cp *certACProvider) checkCertFrozenList(certChain []*bcx509.Certificate) error {
	if len(certChain) < 1 {
		return fmt.Errorf("given certificate chain is empty")
	}
	_, ok := cp.frozenList.Load(string(certChain[0].Raw))
	if ok {
		return fmt.Errorf("certificate is frozen")
	}
	return nil
}

// Check whether the provided member is a valid member of this group
func (cp *certACProvider) verifyMember(mem MemberInterface) ([]*bcx509.Certificate, error) {
	if mem == nil {
		return nil, fmt.Errorf("invalid member: member should not be nil")
	}
	certMember, ok := mem.(*certificateMember)
	if !ok {
		return nil, fmt.Errorf("invalid member: member type err")
	}

	orgIdFromCert := certMember.cert.Subject.Organization[0]
	org := cp.acService.getOrgInfoByOrgId(orgIdFromCert)

	// the Third-party CA
	if certMember.cert.IsCA && org == nil {
		//cp.acService.log.Info("the Third-party CA verify the member")
		certChain := []*bcx509.Certificate{certMember.cert}
		err := cp.checkCRL(certChain)
		if err != nil {
			return nil, err
		}

		err = cp.checkCertFrozenList(certChain)
		if err != nil {
			return nil, err
		}

		return certChain, nil
	}

	if mem.GetOrgId() != orgIdFromCert {
		return nil, fmt.Errorf(
			"signer does not belong to the organization it claims [claim: %s, certificate: %s]",
			mem.GetOrgId(),
			orgIdFromCert,
		)
	}

	if org == nil {
		return nil, fmt.Errorf("no orgnization found")
	}

	certChains, err := certMember.cert.Verify(cp.opts)
	if err != nil {
		return nil, fmt.Errorf("not ac valid certificate from trusted CAs: %v", err)
	}

	if len(org.(*organization).trustedRootCerts) <= 0 {
		return nil, fmt.Errorf("no trusted root: please configure trusted root certificate")
	}

	certChain := cp.findCertChain(org.(*organization), certChains)
	if certChain != nil {
		return certChain, nil
	}
	return nil, fmt.Errorf("authentication failed, signer does not belong to the organization it claims"+
		" [claim: %s]", mem.GetOrgId())
}

func (cp *certACProvider) findCertChain(org *organization, certChains [][]*bcx509.Certificate) []*bcx509.Certificate {
	for _, chain := range certChains {
		rootCert := chain[len(chain)-1]
		_, ok := org.trustedRootCerts[string(rootCert.Raw)]
		if ok {
			var err error
			// check CRL and frozen list
			err = cp.checkCRL(chain)
			if err != nil {
				//cp.acService.log.Warnf("authentication failed, CRL: %v", err)
				continue
			}
			err = cp.checkCertFrozenList(chain)
			if err != nil {
				//cp.acService.log.Warnf("authentication failed, certificate frozen list: %v", err)
				continue
			}
			return chain
		}
	}
	return nil
}

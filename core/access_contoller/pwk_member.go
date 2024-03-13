package access_contoller

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	bccrypto "my_simplechain/core/access_contoller/crypto"
	"my_simplechain/core/access_contoller/crypto/asym"
	"sync"
)

// an instance whose member type is a certificate
// 定义了一个区块链网络成员的核心属性，包括其身份、所属组织、公钥信息、角色和使用的哈希类型。
// 这样的设计使得区块链网络能够高效地进行身份验证、权限控制和数据完整性校验
type pkMember struct {

	// pem public key
	// 成员的唯一标识符，通常是基于成员的公钥信息生成的。这个ID可以用来在网络中唯一地标识这个成员
	id string

	// organization identity who owns this member
	// orgId表示拥有这个成员的组织的标识符。在多组织的区块链网络中，这个字段用于区分成员属于哪个组织
	orgId string

	// public key uid
	// uid是公钥的唯一标识符，用于在可能存在多个公钥的情况下区分不同的公钥
	uid string

	// the public key used for authentication
	// 存储用于身份验证的公钥。在区块链网络中，公钥和私钥对用于签名和验证签名，以确保交易或消息的真实性和完整性
	pk bccrypto.PublicKey

	// role of this member
	// role字段表示这个成员在网络中的角色。不同的角色可能有不同的权限和责任
	role Role

	// hash type from chain configuration
	// hashType字段指定了链配置中使用的哈希类型。哈希函数用于生成数据的哈希值，是区块链技术中确保数据不可篡改的关键机制之一
	hashType string
}

func (pm *pkMember) GetPk() bccrypto.PublicKey {
	return pm.pk
}

// GetMemberId returns the identity of this member (non-uniqueness)
func (pm *pkMember) GetMemberId() string {
	return pm.id
}

// GetOrgId returns the organization id which this member belongs to
func (pm *pkMember) GetOrgId() string {
	return pm.orgId
}

// GetRole returns roles of this member
func (pm *pkMember) GetRole() Role {
	return pm.role
}

// GetUid returns the identity of this member (unique)
func (pm *pkMember) GetUid() string {
	return pm.uid
}

func newPkMemberFromAcs(member *Member, adminList, consensusList *sync.Map,
	acs *accessControlService) (*pkMember, error) {

	// 检查成员类型是否为公钥，如果不是则返回错误
	if member.MemberType != MemberType_PUBLIC_KEY {
		return nil, fmt.Errorf("new public key member failed: memberType and authType do not match")
	}

	// 尝试从成员信息中解析公钥，如果解析失败则返回
	pk, err := asym.PublicKeyFromPEM(member.MemberInfo)
	if err != nil {
		return nil, fmt.Errorf("new public key member failed: parse the public key from PEM failed")
	}

	// 获取公钥的字节表示
	pkBytes, err := pk.Bytes()
	if err != nil {
		return nil, fmt.Errorf("new public key member failed: %s", err.Error())
	}

	// 尝试从管理员列表中加载公钥对应的管理员成员，如果存在，则创建并返回一个新的公钥成员实例
	adminMember, ok := adminList.Load(hex.EncodeToString(pkBytes))
	if ok {
		admin, _ := adminMember.(*adminMemberModel)
		return newPkMemberFromParam(admin.orgId, admin.pkBytes, RoleAdmin, acs.hashType)
	}

	// 如果公钥不是管理员，则尝试创建与公钥关联的 libp2p 节点 ID
	//var nodeId string
	//nodeId, err = CreateLibp2pPeerIdWithPublicKey(pk)
	//if err != nil {
	//	return nil, fmt.Errorf("new public key member failed: create libp2p peer id with pk failed")
	//}
	//
	//// 尝试从共识列表中加载节点 ID 对应的共识成员，如果存在，则创建并返回一个新的成员实例
	//consensusMember, ok := consensusList.Load(nodeId)
	//if ok {
	//	consensus, _ := consensusMember.(*consensusMemberModel)
	//	return newPkMemberFromParam(consensus.orgId, pkBytes, RoleConsensusNode, acs.hashType)
	//}

	// 如果公钥既不是管理员也不是共识成员，则尝试从链上读取公钥信息
	//publicKeyIdex := pubkeyHash(pkBytes)
	//publicKeyInfoBytes, err := acs.dataStore.ReadObject(syscontract.SystemContract_PUBKEY_MANAGE.String(),
	//	[]byte(publicKeyIdex))
	//if err != nil {
	//	return nil, fmt.Errorf("new public key member failed: %s", err.Error())
	//}

	// 如果链上不存在该公钥信息，则返回错误
	//if publicKeyInfoBytes == nil {
	//	return nil, fmt.Errorf("new public key member failed: the public key doesn't belong to a member on chain")
	//}

	// 解析链上的公钥信息
	//var publickInfo PKInfo
	//err = proto.Unmarshal(publicKeyInfoBytes, &publickInfo)
	//if err != nil {
	//	return nil, fmt.Errorf("new public key member failed: %s", err.Error())
	//}
	//
	//// 根据链上公钥信息创建并返回一个新的公钥成员实例
	//return newPkMemberFromParam(publickInfo.OrgId, pkBytes,
	//	protocol.Role(publickInfo.Role), acs.hashType)

	return nil, nil
}

// 定义函数newPkMemberFromParam，它接收一个组织ID、公钥字节、角色和哈希类型，返回一个公钥成员和可能的错误。
func newPkMemberFromParam(orgId string, pkBytes []byte, role Role,
	hashType string) (*pkMember, error) {

	// 尝试从哈希算法映射中查找给定的哈希类型
	hash, ok := bccrypto.HashAlgoMap[hashType]
	if !ok {
		return nil, fmt.Errorf("sign failed: unsupport hash type")
	}

	// 初始化一个pkMember结构体实例。
	var pkMem pkMember
	pkMem.orgId = orgId
	pkMem.hashType = hashType

	// 尝试从公钥字节中解析公钥，如果失败，则返回错误。
	pk, err := asym.PublicKeyFromDER(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("setup pk member failed, err: %s", err.Error())
	}

	// 设置pkMember结构体的公钥和角色字段。
	pkMem.pk = pk
	pkMem.role = role

	// 计算公钥的主题密钥标识符（SKI），这通常用于唯一标识公钥。
	ski, err := ComputeSKI(hash, pk.ToStandardKey())
	if err != nil {
		return nil, fmt.Errorf("setup pk member failed, err: %s", err.Error())
	}

	// 将SKI编码为十六进制字符串，并设置为pkMember的UID。
	pkMem.uid = hex.EncodeToString(ski)

	// 将公钥转换为PEM格式的字符串，如果失败，则返回错误。
	pkPem, err := pk.String()
	if err != nil {
		return nil, fmt.Errorf("setup pk member failed, err: %s", err.Error())
	}

	// 设置pkMember的ID为公钥的PEM字符串。
	pkMem.id = pkPem

	// 返回初始化完成的pkMember实例和nil错误。
	return &pkMem, nil
}

func pubkeyHash(pubkey []byte) string {
	pkHash := sha256.Sum256(pubkey)
	strPkHash := base58.Encode(pkHash[:])
	return strPkHash
}

//// CreateLibp2pPeerIdWithPublicKey create a peer.ID with crypto.PublicKey.
//func CreateLibp2pPeerIdWithPublicKey(publicKey crypto.PublicKey) (string, error) {
//	pubKey, err := ParseGoPublicKeyToPubKey(publicKey.ToStandardKey())
//	if err != nil {
//		return "", err
//	}
//	pid, err := libp2ppeer.IDFromPublicKey(pubKey)
//	if err != nil {
//		return "", err
//	}
//	return pid.Pretty(), err
//}
//
//// ParseGoPublicKeyToPubKey parse a go crypto PublicKey to a libp2p crypto PubKey.
//func ParseGoPublicKeyToPubKey(publicKey bccrypto.PublicKey) (libp2pcrypto.PubKey, error) {
//	switch p := publicKey.(type) {
//	case *ecdsa.PublicKey:
//		if p.Curve == sm2.P256Sm2() {
//			b, err := tjx509.MarshalPKIXPublicKey(p)
//			if err != nil {
//				return nil, err
//			}
//			pub, err := tjx509.ParseSm2PublicKey(b)
//			if err != nil {
//				return nil, err
//			}
//			return libp2pcrypto.NewSM2PublicKey(pub), nil
//		}
//		if p.Curve == btcec.S256() {
//			return (*libp2pcrypto.Secp256k1PublicKey)(p), nil
//		}
//		return libp2pcrypto.NewECDSAPublicKey(p), nil
//
//	case *sm2.PublicKey:
//		return libp2pcrypto.NewSM2PublicKey(p), nil
//	case *rsa.PublicKey:
//		return libp2pcrypto.NewRsaPublicKey(*p), nil
//	default:
//		return nil, errors.New("unsupported public key type")
//	}
//}

type signingPKMember struct {
	// Extends Identity
	pkMember

	// Sign the message
	sk bccrypto.PrivateKey
}

// Verify verifies a signature over some message using this member
func (pm *pkMember) Verify(hashType string, msg []byte, sig []byte) error {
	hash, ok := bccrypto.HashAlgoMap[hashType]
	if !ok {
		return fmt.Errorf("cert member verify signature failed: unsupport hash type")
	}

	ok, err := pm.pk.VerifyWithOpts(msg, sig, &bccrypto.SignOpts{
		Hash: hash,
		UID:  bccrypto.CRYPTO_DEFAULT_UID,
	})
	if err != nil {
		return fmt.Errorf("cert member verify signature failed: [%s]", err.Error())
	}
	if !ok {
		return fmt.Errorf("cert member verify signature failed: invalid signature")
	}
	return nil
}

// When using public key instead of certificate,
// hashType is used to specify the hash algorithm while the signature algorithm is decided by the public key itself.
func (spm *signingPKMember) Sign(hashType string, msg []byte) ([]byte, error) {
	hash, ok := bccrypto.HashAlgoMap[hashType]
	if !ok {
		return nil, fmt.Errorf("sign failed: unsupport hash type")
	}
	return spm.sk.SignWithOpts(msg, &bccrypto.SignOpts{
		Hash: hash,
		UID:  bccrypto.CRYPTO_DEFAULT_UID,
	})
}

// GetMember returns Member
func (pm *pkMember) GetMember() (*Member, error) {
	memberInfo, err := pm.pk.String()
	if err != nil {
		return nil, fmt.Errorf("get pb member failed: %s", err.Error())
	}
	return &Member{
		OrgId:      pm.orgId,
		MemberInfo: []byte(memberInfo),
		MemberType: MemberType_PUBLIC_KEY,
	}, nil
}

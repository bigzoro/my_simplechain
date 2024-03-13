package access_contoller

import (
	//bcx509 "github.com/simplechain-org/go-simplechain/core/access_contoller/crypto/x509"
	//"github.com/simplechain-org/go-simplechain/params"
	bcx509 "my_simplechain/core/access_contoller/crypto/x509"
	"my_simplechain/params"
)

type ResourcePolicy struct {
	ResourceName string
	Policy       policy
}

type TrustRootConfig struct {
	OrgId string
	Root  []string
}

type organization struct {
	// Name of this group
	id string

	// Trusted certificates or white list
	//trustedRootCerts map[string]*bcx509.Certificate
	trustedRootCerts map[string]*bcx509.Certificate

	// Trusted intermediate certificates or white list
	//trustedIntermediateCerts map[string]*bcx509.Certificate
	trustedIntermediateCerts map[string]*bcx509.Certificate
}

type TrustMemberConfig struct {
	// member info
	MemberInfo string
	// oranization ideftifier
	OrgId  string
	Role   string
	NodeId string
}

// 信任成员缓存
type trustMemberCached struct {
	trustMember *params.TrustMemberConfig
	cert        *bcx509.Certificate
}

type MemberType int32

type Member struct {
	// organization identifier of the member
	OrgId string
	// member type
	MemberType MemberType
	// member identity related info bytes
	MemberInfo []byte
}

type EndorsementEntry struct {
	// signer
	Signer *Member
	// signature
	Signature []byte
}

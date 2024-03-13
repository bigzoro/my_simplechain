package access_contoller

type Rule string
type Role string

const (
	//X509 cert
	MemberType_CERT MemberType = 0
	//cert hash
	MemberType_CERT_HASH MemberType = 1
	//public key
	MemberType_PUBLIC_KEY MemberType = 2
	//did
	MemberType_DID MemberType = 3
	//alias
	MemberType_ALIAS MemberType = 4
	//address
	MemberType_ADDR MemberType = 5

	ResourceNameUnknown          = "UNKNOWN"
	ResourceNameReadData         = "READ"
	ResourceNameWriteData        = "WRITE"
	ResourceNameP2p              = "P2P"
	ResourceNameConsensusNode    = "CONSENSUS"
	ResourceNameAdmin            = "ADMIN"
	ResourceNameUpdateConfig     = "CONFIG"
	ResourceNameUpdateSelfConfig = "SELF_CONFIG"
	ResourceNameAllTest          = "ALL_TEST"

	RoleAdmin         Role = "ADMIN"
	RoleClient        Role = "CLIENT"
	RoleLight         Role = "LIGHT"
	RoleConsensusNode Role = "CONSENSUS"
	RoleCommonNode    Role = "COMMON"
	RoleContract      Role = "CONTRACT"

	RuleMajority  Rule = "MAJORITY"
	RuleAll       Rule = "ALL"
	RuleAny       Rule = "ANY"
	RuleSelf      Rule = "SELF"
	RuleForbidden Rule = "FORBIDDEN"
	RuleDelete    Rule = "DELETE"
)

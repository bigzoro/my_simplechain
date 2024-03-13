package access_contoller

import "github.com/bigzoro/my_simplechain/core/access_contoller/crypto"

const (
	//PermissionedWithCert permissioned with certificate
	PermissionedWithCert string = "permissionedwithcert"

	//PermissionedWithKey permissioned with public key
	PermissionedWithKey string = "permissionedwithkey"

	// Public public key
	Public string = "public"

	// Identity (1.X PermissionedWithCert)
	Identity string = "identity"
)

type AccessControlProvider interface {

	// GetHashAlg return hash algorithm the access control provider uses
	GetHashAlg() string

	// ValidateResourcePolicy checks whether the given resource policy is valid
	//ValidateResourcePolicy(resourcePolicy *params.ResourcePolicy) bool

	// LookUpPolicy returns corresponding policy configured for the given resource name
	//LookUpPolicy(resourceName string) (*params.Policy, error)

	// LookUpExceptionalPolicy returns corresponding exceptional policy configured for the given resource name
	//LookUpExceptionalPolicy(resourceName string) (*params.Policy, error)

	//GetAllPolicy returns all policies
	//GetAllPolicy() (map[string]*params.Policy, error)

	// CreatePrincipal creates a principal for one time authentication
	CreatePrincipal(resourceName string, endorsements []*EndorsementEntry, message []byte) (Principal, error)

	// CreatePrincipalForTargetOrg creates a principal for "SELF" type policy,
	// which needs to convert SELF to a sepecific organization id in one authentication
	//CreatePrincipalForTargetOrg(resourceName string, endorsements []*common.EndorsementEntry, message []byte,
	//	targetOrgId string) (Principal, error)

	//GetValidEndorsements filters all endorsement entries and returns all valid ones
	//GetValidEndorsements(principal Principal) ([]*common.EndorsementEntry, error)

	// VerifyPrincipal verifies if the policy for the resource is met
	VerifyPrincipal(principal Principal) (bool, error)

	// RefineEndorsements verifies endorsements
	//RefineEndorsements(endorsements []*common.EndorsementEntry, msg []byte) []*common.EndorsementEntry

	// NewMember creates a member from pb Member
	//NewMember(member *pbac.Member) (Member, error)

	//GetMemberStatus get the status information of the member
	//GetMemberStatus(member *pbac.Member) (pbac.MemberStatus, error)

	//VerifyRelatedMaterial verify the member's relevant identity material
	//VerifyRelatedMaterial(verifyType pbac.VerifyType, data []byte) (bool, error)
}

// Principal contains all information related to one time verification
type Principal interface {
	// GetResourceName returns resource name of the verification
	GetResourceName() string

	// GetEndorsement returns all endorsements (signatures) of the verification
	GetEndorsement() []*EndorsementEntry

	// GetMessage returns signing data of the verification
	GetMessage() []byte

	// GetTargetOrgId returns target organization id of the verification if the verification is for a specific organization
	GetTargetOrgId() string
}

// Member is the identity of a node or user.
type MemberInterface interface {
	// GetMemberId returns the identity of this member (non-uniqueness)
	GetMemberId() string

	// GetOrgId returns the organization id which this member belongs to
	GetOrgId() string

	// GetRole returns roles of this member
	GetRole() Role

	// GetUid returns the identity of this member (unique)
	GetUid() string

	// Verify verifies a signature over some message using this member
	Verify(hashType string, msg []byte, sig []byte) error

	// GetMember returns Member
	GetMember() (*Member, error)

	//GetPk returns public key
	GetPk() crypto.PublicKey
}

type SigningMember interface {
	// Extends Member interface
	MemberInterface

	// Sign signs the message with the given hash type and returns signature bytes
	Sign(hashType string, msg []byte) ([]byte, error)
}

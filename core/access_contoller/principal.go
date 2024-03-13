package access_contoller

type principal struct {
	// 此字段代表主体关联的资源名称或标识符。在区块链或分布式账本的上下文中
	// 资源可以是智能合约、数字资产或任何需要访问控制的实体。
	// resourceName用于指定主体试图访问或与之交互的资源，使得可以实现细粒度的访问控制策略
	resourceName string
	endorsement  []*EndorsementEntry
	message      []byte

	// 目标组织
	targetOrg string
}

// GetResourceName returns principal resource name
func (p *principal) GetResourceName() string {
	return p.resourceName
}

// GetEndorsement returns principal endorsement
func (p *principal) GetEndorsement() []*EndorsementEntry {
	return p.endorsement
}

// GetMessage returns principal message
func (p *principal) GetMessage() []byte {
	return p.message
}

// GetTargetOrgId returns principal target orgId
func (p *principal) GetTargetOrgId() string {
	return p.targetOrg
}

package access_contoller

type policy struct {
	rule     Rule
	orgList  []string
	roleList []Role
}

func (p *policy) GetRule() Rule {
	return p.rule
}

func (p *policy) GetOrgList() []string {
	return p.orgList
}

func (p *policy) GetRoleList() []Role {
	return p.roleList
}

func newPolicy(rule Rule, orgList []string, roleList []Role) *policy {
	return &policy{
		rule:     rule,
		orgList:  orgList,
		roleList: roleList,
	}
}

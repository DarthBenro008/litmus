package entities

type ServerConfigs struct {
	ID                    string `bson:"_id,omitempty" json:"_id"`
	GlobalOAuthConfig     bool   `bson:"global_oauth_config" json:"global_oauth_config"`
	RequiredOAuthApproval bool   `bson:"required_oauth_approval" json:"required_oauth_approval"`
}

func (c ServerConfigs) DecideOAuthStatus() bool {
	if c.RequiredOAuthApproval {
		return false
	}
	return c.GlobalOAuthConfig
}

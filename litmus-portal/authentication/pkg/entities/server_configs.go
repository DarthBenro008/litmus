package entities

type ServerConfigs struct {
	GlobalOAuthConfig bool `bson:"global_oauth_config,omitempty" json:"global_oauth_config,omitempty"`
}
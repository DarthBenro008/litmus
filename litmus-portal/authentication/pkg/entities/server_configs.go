package entities

type ServerConfigs struct {
	ID                string `bson:"_id,omitempty" json:"_id"`
	GlobalOAuthConfig bool   `bson:"global_oauth_config" json:"global_oauth_config"`
}

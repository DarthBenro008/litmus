package server_configs

import (
	"litmus/litmus-portal/authentication/pkg/entities"
)

type Service interface {
	GetServerConfigs() (*entities.ServerConfigs, error)
	SetServerConfigs(configs entities.ServerConfigs) error
}

type service struct {
	repository Repository
}

func (s service) GetServerConfigs() (*entities.ServerConfigs, error) {
	return s.GetServerConfigs()
}

func (s service) SetServerConfigs(configs entities.ServerConfigs) error {
	return s.SetServerConfigs(configs)
}

// NewService creates a new instance of this service
func NewService(r Repository) Service {
	return &service{
		repository: r,
	}
}

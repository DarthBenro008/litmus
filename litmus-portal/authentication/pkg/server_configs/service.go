package server_configs

import (
	"litmus/litmus-portal/authentication/pkg/entities"
)

type Service interface {
	GetAllServerConfigs() (*entities.ServerConfigs, error)
	SetServerConfigs(configs *entities.ServerConfigs) error
	GetGlobalOAuthConfig() (bool, error)
}

type service struct {
	repository Repository
}

func (s service) GetAllServerConfigs() (*entities.ServerConfigs, error) {
	return s.repository.GetServerConfigs()
}

func (s service) SetServerConfigs(configs *entities.ServerConfigs) error {
	return s.repository.SetServerConfigs(configs)
}

func (s service) GetGlobalOAuthConfig() (bool, error) {
	configs, err := s.GetAllServerConfigs()
	if err != nil {
		return false, err
	}
	return configs.GlobalOAuthConfig, nil
}

// NewService creates a new instance of this service
func NewService(r Repository) Service {
	return &service{
		repository: r,
	}
}

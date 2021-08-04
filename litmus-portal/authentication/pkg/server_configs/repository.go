package server_configs

import (
	"context"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"litmus/litmus-portal/authentication/pkg/entities"
)

type Repository interface {
	GetServerConfigs() (*entities.ServerConfigs, error)
	SetServerConfigs(configs *entities.ServerConfigs) error
}

type repository struct {
	Collection *mongo.Collection
}

func (r repository) GetServerConfigs() (*entities.ServerConfigs, error) {
	var result = entities.ServerConfigs{}
	_, findErr := r.Collection.Find(context.Background(), bson.M{})
	if findErr != nil {
		return nil, findErr
	}
	return &result, nil
}

func (r repository) SetServerConfigs(configs *entities.ServerConfigs) error {
	opts := options.Update().SetUpsert(true)
	_, err := r.Collection.UpdateOne(context.Background(), bson.M{}, bson.M{"$set": configs}, opts)
	if err != nil {
		println(err)
		return err
	}
	return nil
}

// NewRepo creates a new instance of this repository
func NewRepo(collection *mongo.Collection) Repository {
	return &repository{
		Collection: collection,
	}
}

func toDoc(v interface{}) (doc *bson.M, err error) {
	data, err := bson.Marshal(v)
	if err != nil {
		return
	}
	err = bson.Unmarshal(data, &doc)
	return
}

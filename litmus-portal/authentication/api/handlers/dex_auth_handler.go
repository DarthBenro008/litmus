package handlers

import (
	"context"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"litmus/litmus-portal/authentication/api/presenter"
	"litmus/litmus-portal/authentication/pkg/entities"
	"litmus/litmus-portal/authentication/pkg/user"
	"litmus/litmus-portal/authentication/pkg/utils"
	"net/http"
)

var (
	state    = "holderState"
	verifier *oidc.IDTokenVerifier
)

func oAuthDexConfig() (*oauth2.Config, error) {
	ctx := oidc.ClientContext(context.Background(), &http.Client{})
	provider, err := oidc.NewProvider(ctx, utils.DexOIDCIssuer)
	if err != nil {
		log.Errorf("OAuth Error: Something went wrong with OIDC provider %s", err)
		return nil, err
	}
	verifier = provider.Verifier(&oidc.Config{ClientID: utils.DexClientID})
	return &oauth2.Config{
		RedirectURL:  utils.DexCallBackURL,
		ClientID:     utils.DexClientID,
		ClientSecret: utils.DexClientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     provider.Endpoint(),
	}, nil
}

// DexLogin handles and redirects to DexServer to proceed with OAuth
func DexLogin() gin.HandlerFunc {
	return func(c *gin.Context) {

		tempState, err := utils.GenerateRandomString(5)
		state = tempState
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		config, err := oAuthDexConfig()
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		url := config.AuthCodeURL(state)
		c.Redirect(http.StatusTemporaryRedirect, url)
	}
}

// DexCallback is the handler that creates/logs in the user from Dex and provides JWT to frontend via a reidirect
func DexCallback(userService user.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Query("state") != state {
			c.Redirect(http.StatusTemporaryRedirect, "/")
		}
		config, err := oAuthDexConfig()
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		token, err := config.Exchange(context.Background(), c.Query("code"))
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Error("OAuth Error: no raw id_token found")
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		idToken, err := verifier.Verify(c, rawIDToken)
		if err != nil {
			log.Error("OAuth Error: no id_token found")
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}

		var claims struct {
			Name     string
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			log.Error("OAuth Error: claims not found")
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		var userData = entities.User{
			Name:     claims.Name,
			Email:    claims.Email,
			UserName: claims.Email,
			Role:     entities.RoleUser,
		}
		signedInUser, err := userService.LoginUser(&userData)
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		jwtToken, err := signedInUser.GetSignedJWT()
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		c.Redirect(http.StatusPermanentRedirect, "/login?jwtToken="+jwtToken)
	}
}

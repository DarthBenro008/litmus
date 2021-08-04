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

const (
	redirectUrl = "/login"
)

type claims struct {
	Name     string
	Email    string `json:"email"`
	Verified bool   `json:"email_verified"`
}

func oAuthDexConfig() (*oauth2.Config, error) {
	ctx := oidc.ClientContext(context.Background(), &http.Client{})
	provider, err := oidc.NewProvider(ctx, utils.OidcIssuer)
	if err != nil {
		log.Errorf("Something wrong with connecting to Dex oidc provider %s", err)
		return nil, err
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: utils.ClientId})
	return &oauth2.Config{
		RedirectURL:  utils.CallbackUrl,
		ClientID:     utils.ClientId,
		ClientSecret: utils.ClientSecret,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     provider.Endpoint(),
	}, nil
}

func DexLogin() gin.HandlerFunc {
	return func(c *gin.Context) {

		tempState, err := utils.GenerateRandomString()
		state = tempState
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}
		url, err := oAuthDexConfig()
		if err != nil {
			c.Redirect(http.StatusTemporaryRedirect, redirectUrl)
			return
		}
		config := url.AuthCodeURL(state)
		c.Redirect(http.StatusTemporaryRedirect, config)
	}
}

func DexCallback(userService user.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Query("state") != state {
			c.Redirect(http.StatusTemporaryRedirect, redirectUrl)
		}
		config, err := oAuthDexConfig()
		if err != nil {
			c.Redirect(http.StatusPermanentRedirect, redirectUrl)
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
			log.Error("no rawIDToken found")
			c.Redirect(http.StatusPermanentRedirect, redirectUrl)
		}
		idToken, err := verifier.Verify(c, rawIDToken)
		if err != nil {
			log.Error("no idToken found")
			c.Redirect(http.StatusPermanentRedirect, redirectUrl)
			return
		}

		var tokenClaims claims
		if err := idToken.Claims(&tokenClaims); err != nil {
			log.Error("no rawIDToken found")
			c.Redirect(http.StatusPermanentRedirect, redirectUrl)
			return
		}
		var userData = entities.User{
			Name:     tokenClaims.Name,
			Email:    tokenClaims.Email,
			UserName: tokenClaims.Email,
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

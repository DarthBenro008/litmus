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
	"os"
)

var (
	state    = "holderState"
	verifier *oidc.IDTokenVerifier
)

func oAuthDexConfig() *oauth2.Config {
	ctx := oidc.ClientContext(context.Background(), &http.Client{})
	provider, err := oidc.NewProvider(ctx, os.Getenv("OIDC_ISSUER"))
	//provider, err := oidc.NewProvider(ctx, "http://127.0.0.1:5556/dex")
	if err != nil {
		log.Panicf("Something wrong with oidc provider %s", err)
	}
	incomingEndpoints := provider.Endpoint()
	incomingEndpoints.AuthURL = "/dex/auth"
	incomingEndpoints.TokenURL = "/dex/token"
	verifier = provider.Verifier(&oidc.Config{ClientID: "example-app"})
	return &oauth2.Config{
		RedirectURL:  "http://localhost:8080/auth/dex/callback",
		ClientID:     "example-app",              //os.Getenv("GOOGLE_OAUTH_CLIENT_ID")
		ClientSecret: "ZXhhbXBsZS1hcHAtc2VjcmV0", //os.Getenv("GOOGLE_OAUTH_CLIENT_SECRET"),
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     provider.Endpoint(),
	}
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
		url := oAuthDexConfig().AuthCodeURL(state)
		c.Redirect(http.StatusTemporaryRedirect, url)
	}
}

func DexCallback(userService user.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Query("state") != state {
			c.Redirect(http.StatusTemporaryRedirect, "/")
		}
		token, err := oAuthDexConfig().Exchange(context.Background(), c.Query("code"))
		if err != nil {
			log.Error(err)
			c.JSON(utils.ErrorStatusCodes[utils.ErrServerError], presenter.CreateErrorResponse(utils.ErrServerError))
			return
		}

		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Error("no rawIDToken found")
		}
		idToken, err := verifier.Verify(c, rawIDToken)
		if err != nil {
			log.Error("no idToken found")
		}

		var claims struct {
			Name     string
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
		}
		if err := idToken.Claims(&claims); err != nil {
			log.Error("no rawIDToken bruh")
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

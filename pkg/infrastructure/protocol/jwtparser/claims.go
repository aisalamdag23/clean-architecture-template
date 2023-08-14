package jwtparser

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type (
	// Represents the claims in JWT Access Token
	AccessTokenClaims struct {
		ID   uuid.UUID `json:"id"`
		Role string    `json:"role"`
		jwt.StandardClaims
	}

	// Represents the claims in JWT Refresh Token
	RefreshTokenClaims struct {
		ID         uuid.UUID `json:"id"`
		RememberMe bool      `json:"remember_me"`
		jwt.StandardClaims
	}

	// Represent email activation token
	ActivationTokenClaims struct {
		ID uuid.UUID `json:"id"`
		jwt.StandardClaims
	}

	// Represent email activation token
	ForgotPasswordClaims struct {
		Email string `json:"email"`
		jwt.StandardClaims
	}
)

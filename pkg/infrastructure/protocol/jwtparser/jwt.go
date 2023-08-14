package jwtparser

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

type JwtParser struct {
	signName   string
	verifyKeys map[string]*rsa.PublicKey
	signKey    *rsa.PrivateKey
}

func NewJWTParser(signName string, publicKeys map[string][]byte, privateKey []byte) (*JwtParser, error) {
	verifyKeys := make(map[string]*rsa.PublicKey)
	for k, publicKey := range publicKeys {
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(publicKey)
		if err != nil {
			return nil, err
		}
		verifyKeys[k] = verifyKey
	}

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, err
	}

	return &JwtParser{
		signName:   signName,
		verifyKeys: verifyKeys,
		signKey:    signKey,
	}, nil
}

func (jp *JwtParser) ParseAccessToken(r *http.Request) (*AccessTokenClaims, error) {
	tokenString := ""

	header := r.Header.Get("Authorization")
	if header != "" {
		tokenString = strings.Split(header, "Bearer ")[1]
	} else {
		cookie, cookieErr := r.Cookie("access_token")
		if cookieErr != nil {
			return nil, cookieErr
		}
		tokenString = cookie.Value
	}

	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	token, err := jwt.Parse(tokenString, VerifyFn(jp.verifyKeys))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		auth := &AccessTokenClaims{}
		if userID, ok := claims["id"]; ok {
			auth.ID = uuid.MustParse(userID.(string))
		}
		if role, ok := claims["role"]; ok {
			auth.Role = role.(string)
		}
		return auth, nil
	}

	return nil, errors.New("invalid token")
}

func (jp *JwtParser) ParseRefreshToken(r *http.Request) (*RefreshTokenClaims, error) {
	tokenString := ""

	cookie, cookieErr := r.Cookie("refresh_token")
	if cookieErr != nil {
		return nil, cookieErr
	}
	tokenString = cookie.Value

	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	token, err := jwt.Parse(tokenString, VerifyFn(jp.verifyKeys))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		auth := &RefreshTokenClaims{}
		if userID, ok := claims["id"]; ok {
			auth.ID = uuid.MustParse(userID.(string))
		}
		if rememberMe, ok := claims["remember_me"]; ok {
			auth.RememberMe, _ = rememberMe.(bool)
		}
		return auth, nil
	}

	return nil, errors.New("invalid token")
}

func (jp *JwtParser) CreateAccessToken(uuid uuid.UUID, role string, expiresAt time.Time) (string, error) {
	accessToken := jwt.New(jwt.SigningMethodRS256)
	accessToken.Claims = AccessTokenClaims{
		ID:   uuid,
		Role: role,
		StandardClaims: jwt.StandardClaims{
			Issuer:    jp.signName,
			ExpiresAt: expiresAt.Unix(),
		},
	}
	return accessToken.SignedString(jp.signKey)
}

func (jp *JwtParser) CreateRefreshToken(uuid uuid.UUID, remember bool, expiresAt time.Time) (string, error) {
	refreshToken := jwt.New(jwt.SigningMethodRS256)
	refreshToken.Claims = RefreshTokenClaims{
		ID:         uuid,
		RememberMe: remember,
		StandardClaims: jwt.StandardClaims{
			Issuer:    jp.signName,
			ExpiresAt: expiresAt.Unix(),
		},
	}
	return refreshToken.SignedString(jp.signKey)
}

func (jp *JwtParser) CreateActivationToken(uuid uuid.UUID) (string, error) {
	activationToken := jwt.New(jwt.SigningMethodRS256)
	activationToken.Claims = ActivationTokenClaims{
		ID: uuid,
		StandardClaims: jwt.StandardClaims{
			Issuer: jp.signName,
		},
	}
	return activationToken.SignedString(jp.signKey)
}

func (jp *JwtParser) ParseActivationToken(tokenString string) (*ActivationTokenClaims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	token, err := jwt.Parse(tokenString, VerifyFn(jp.verifyKeys))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		auth := &ActivationTokenClaims{}
		if userID, ok := claims["id"]; ok {
			auth.ID = uuid.MustParse(userID.(string))
		}
		return auth, nil
	}

	return nil, errors.New("invalid token")
}

func (jp *JwtParser) CreateForgotPasswordToken(email string) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims = ForgotPasswordClaims{
		Email: email,
		StandardClaims: jwt.StandardClaims{
			Issuer:   jp.signName,
			IssuedAt: time.Now().Unix(),
		},
	}
	return token.SignedString(jp.signKey)
}

func (jp *JwtParser) ParseForgotPasswordToken(tokenString string) (*ForgotPasswordClaims, error) {
	if tokenString == "" {
		return nil, errors.New("empty token")
	}

	token, err := jwt.Parse(tokenString, VerifyFn(jp.verifyKeys))
	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		auth := &ForgotPasswordClaims{}
		if email, ok := claims["email"]; ok {
			auth.Email = email.(string)
		}
		if issuedAt, ok := claims["iat"]; ok {
			auth.IssuedAt = int64(issuedAt.(float64))
		}
		return auth, nil
	}

	return nil, errors.New("invalid token")
}

func VerifyFn(verifyKeys map[string]*rsa.PublicKey) func(*jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		var (
			iss interface{}
			ok  bool
		)
		if iss, ok = token.Claims.(jwt.MapClaims)["iss"]; !ok {
			return nil, errors.New("invalid token")
		}
		if verifyKey, ok := verifyKeys[iss.(string)]; ok {
			return verifyKey, nil
		}
		return nil, errors.New("invalid issuer")
	}
}

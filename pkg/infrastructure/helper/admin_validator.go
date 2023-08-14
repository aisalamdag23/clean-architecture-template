package helper

import (
	"errors"
	"strings"
)

// UserInstance ...
type UserInstance struct {
	IsAdmin bool
	Role    string
	Error   error
}

// NewRoleChecker ...
func NewRoleChecker(role string) (*UserInstance, error) {
	user := UserInstance{}

	user.initRole(role)
	user.initIsAdmin()

	if user.Error != nil {
		return nil, user.Error
	}

	return &user, nil
}

func (u *UserInstance) initRole(role string) {
	if role == "" {
		u.Error = errors.New("Invalid role")
		return
	}

	u.Role = role
}

func (u *UserInstance) initIsAdmin() {
	u.IsAdmin = (strings.ToLower(u.Role) == "admin" || strings.ToLower(u.Role) == "bir_admin")
}

func (u UserInstance) IsUserAdmin() bool {
	return u.IsAdmin
}

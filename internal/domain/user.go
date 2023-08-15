package domain

import (
	"context"
	"time"

	"github.com/lib/pq"

	"github.com/google/uuid"
)

type (
	UserRepository interface {
		Create(ctx context.Context, user Registration) error
		Update(ctx context.Context, user User) error
		GetByEmailWithPassword(ctx context.Context, email string) (*UserWithPassword, error)
		GetByID(ctx context.Context, transactionID uuid.UUID) (*User, error)
		Activate(ctx context.Context, transactionID uuid.UUID) error
		GetAll(ctx context.Context, mapQuery map[string]string) (*UsersList, error)
	}

	UserService interface {
		Login(ctx context.Context, login Login) (*JWT, error)
		Create(ctx context.Context, user Registration) (*User, error)
		Update(ctx context.Context, user User) (*User, error)
		GetByID(ctx context.Context, transactionID uuid.UUID) (*User, error)
		GetAll(ctx context.Context, userID uuid.UUID, params map[string][]string, validators map[string]int) (*UsersList, []string, error)
	}

	User struct {
		ID             uuid.UUID   `json:"id"`
		Email          string      `json:"email" db:"email" validate:"required,email,max=50"`
		FirstName      string      `json:"first_name" db:"first_name" validate:"required,min=2,max=32"`
		MiddleName     string      `json:"middle_name" db:"middle_name" validate:"max=32"`
		LastName       string      `json:"last_name" db:"last_name" validate:"required,min=2,max=32"`
		Address        string      `json:"address" db:"address" validate:"required,min=5,max=70"`
		City           string      `json:"city" db:"city" validate:"required,min=3,max=50"`
		Country        string      `json:"country" db:"country" validate:"required,min=3,max=50"`
		TIN            string      `json:"tin" db:"tin" validate:"required,min=9,max=12"`
		ContactNum     string      `json:"contact_num" db:"contact_num" validate:"required,min=8,max=20"`
		RDOCode        string      `json:"rdo_code" db:"rdo_code" validate:"required,min=3,max=5"`
		AccountType    string      `json:"account_type" db:"account_type" validate:"required,max=15"`
		CorpName       string      `json:"corp_name" db:"corp_name" validate:"max=50"`
		CorpAddress    string      `json:"corp_address" db:"corp_address" validate:"max=255"`
		AccountStatus  bool        `json:"account_status" db:"account_status"`
		DateRegistered time.Time   `json:"date_registered" db:"date_registered"`
		DateActivated  pq.NullTime `json:"-" db:"date_activated"`
		Role           string      `json:"role" db:"role"`
	}

	UserAccount struct {
		User
		DateActivated time.Time `json:"date_activated"`
	}

	UserWithPassword struct {
		User
		Password            string
		PasswordChangedDate pq.NullTime `db:"password_changed_date"`
	}

	Registration struct {
		User
		Password string `json:"password" validate:"required,max=32,min=12"`
	}

	Login struct {
		Email      string `json:"email" validate:"required,email,max=50"`
		Password   string `json:"password" validate:"required,max=32,min=12"`
		RememberMe bool   `json:"remember_me"`
	}

	JWT struct {
		AccessToken      string    `json:"access_token"`
		RefreshToken     string    `json:"refresh_token"`
		ExpiresAt        time.Time `json:"expires_at"`
		RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	}

	// UsersList response for get all users
	UsersList struct {
		TotalRows  int    `json:"total_rows"`
		TotalPages int    `json:"total_pages"`
		Users      []User `json:"users"`
	}

	// ActivityLog user logs
	ActivityLog struct {
		ID        int       `json:"id"`
		UserID    uuid.UUID `json:"user_id"`
		Log       string    `json:"log"`
		Action    string    `json:"action"`
		CreatedAt time.Time `json:"created_at"`
	}

	// DeactivateLog log format
	DeactivateLog struct {
		Reason    string    `json:"reason"`
		Action    string    `json:"action"`
		UpdatedBy uuid.UUID `json:"updated_by"`
		AdminName string    `json:"admin_name"`
	}
)

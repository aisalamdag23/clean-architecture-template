package user

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"

	"github.com/aisalamdag23/clean-architecture-template/pkg/infrastructure/helper"
	"github.com/aisalamdag23/clean-architecture-template/pkg/infrastructure/protocol/jwtparser"

	"github.com/google/uuid"

	"github.com/aisalamdag23/clean-architecture-template/internal/domain"
	"github.com/aisalamdag23/clean-architecture-template/internal/domain/interr"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
)

type service struct {
	repository  domain.UserRepository
	jwtParser   jwtparser.JwtParser
	frontendUrl string
	loginExp    uint // minutes
	rememberExp uint // minutes
}

// NewService creates a new Service for calculation configuration
func NewService(repository domain.UserRepository, jwtParser jwtparser.JwtParser, frontendUrl string, loginExp uint, rememberExp uint) domain.UserService {
	return &service{repository, jwtParser, frontendUrl, loginExp, rememberExp}
}

// GetByID ...
func (s *service) GetByID(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	logger.WithField(ctx, "bir.user.id", userID)
	return s.repository.GetByID(ctx, userID)
}

// GetAll ...
func (s *service) GetAll(ctx context.Context, userID uuid.UUID, params map[string][]string, validators map[string]int) (*domain.UsersList, []string, error) {
	// get user
	user, err := s.repository.GetByID(ctx, userID)

	if err != nil {
		return nil, []string{}, interr.NotFoundErr
	}
	// check role
	role, err := helper.NewRoleChecker(user.Role)
	if !role.IsUserAdmin() || err != nil {
		return nil, []string{}, interr.UnauthorizeErr
	}

	var invalidValue []string
	var dateQCntTemp = validators["date_registered"]
	var mapQuery = make(map[string]string)
	var hasIDParam = false

	// checks the key value pairs from query params
	for k, v := range params {
		mapQuery[k] = ""
		for _, val := range v {
			if (strings.ToLower(k) == "date_registered" || strings.ToLower(k) == "date_activated") && dateQCntTemp >= len(v) {
				// accepted date composition yyyy-mm-dd
				if len(val) > 3 && strings.ToLower(val[0:3]) == "eq:" && validators[strings.ToLower(k)] == 2 {
					// check if parsable to time
					rDate := strings.Replace(strings.ToLower(val), "eq:", "", 1)

					validTime, err := time.Parse("2006-01-02", rDate)
					if err == nil {
						// valid
						mapQuery[k] += " DATE(CONVERT_TZ(" + strings.ToLower(k) + ", '+00:00','+8:00')) = DATE('" + validTime.Format("2006-01-02") + "')"
						validators[strings.ToLower(k)] = 0
						continue
					}
				}
				// date fields should either only be eq or fr: and to:
				if len(val) > 3 && (strings.ToLower(val[0:3]) == "fr:" || strings.ToLower(val[0:3]) == "to:") && validators[strings.ToLower(k)] > 0 {

					before, equal := areDatesConsecutiveOrEqual(params[strings.ToLower(k)])

					if before || equal {
						// valid
						rDate := strings.Replace(strings.ToLower(val), strings.ToLower(val[0:3]), "", 1)

						validTime, _ := time.Parse("2006-01-02", rDate)

						if before {
							if strings.ToLower(val[0:3]) == "fr:" {
								mapQuery[k] += " DATE(CONVERT_TZ(" + strings.ToLower(k) + ", '+00:00','+8:00')) BETWEEN"
							}
							if strings.ToLower(val[0:3]) == "to:" {
								mapQuery[k] += " AND"
							}

							mapQuery[k] += " DATE('" + validTime.Format("2006-01-02") + "')"
						} else {
							mapQuery[k] = " DATE(CONVERT_TZ(" + strings.ToLower(k) + ", '+00:00','+8:00')) = DATE('" + validTime.Format("2006-01-02") + "')"
						}

						validators[strings.ToLower(k)]--
						continue
					}
				}

			} else if (strings.ToLower(k) == "limit" || strings.ToLower(k) == "page") && validators[strings.ToLower(k)] >= len(v) {
				// limit and page should only be intd
				intRes, err := strconv.Atoi(val)
				if err == nil {
					// valid
					mapQuery[k] = fmt.Sprintf("%d", intRes)
					continue
				}
			} else if strings.ToLower(k) == "id" {
				// only accept :eq
				if len(val) > 3 && strings.ToLower(val[0:3]) == "eq:" {
					// valid
					if len(mapQuery[k]) > 0 {
						mapQuery[k] += " OR "
					}

					strVal := strings.Replace(strings.ToLower(val), "eq:", "", 1)
					mapQuery[k] = fmt.Sprintf(" id = UUID_TO_BIN('%s') ", strVal)
					hasIDParam = true
					continue
				}
			} else {
				// strings fields should only accept eq (specific) or has (contains)
				if len(val) > 3 && (strings.ToLower(val[0:3]) == "eq:" || strings.ToLower(val[0:4]) == "has:") {

					if len(mapQuery[k]) > 0 {
						mapQuery[k] += " OR "
					}

					if strings.ToLower(val[0:3]) == "eq:" {
						strVal := strings.Replace(strings.ToLower(val), "eq:", "", 1)
						mapQuery[k] += strings.ToLower(k) + " = '" + strVal + "' "
					}

					if strings.ToLower(val[0:4]) == "has:" {
						strVal := strings.Replace(strings.ToLower(val), "has:", "", 1)
						mapQuery[k] += strings.ToLower(k) + " LIKE '%" + strVal + "%' "
					}

					// valid
					continue
				} else {
					// sort goes here
					if strings.ToLower(k) == "sort" && len(v) == 1 {
						switch strings.ToLower(val) {
						case "date_registered_desc":
							mapQuery[k] = " date_registered DESC "
						case "date_activated_desc":
							mapQuery[k] = " date_activated DESC "
						case "date_activated_asc":
							mapQuery[k] = " date_activated ASC "
						case "name_desc":
							mapQuery[k] = " last_name DESC, first_name DESC, middle_name DESC "
						case "name_asc":
							mapQuery[k] = " last_name ASC, first_name ASC, middle_name ASC "
						case "city_desc":
							mapQuery[k] = " city DESC "
						case "city_asc":
							mapQuery[k] = " city ASC "
						case "rdo_code_desc":
							mapQuery[k] = " rdo_code DESC "
						case "rdo_code_asc":
							mapQuery[k] = " rdo_code ASC "
						case "account_type_desc":
							mapQuery[k] = " account_type DESC "
						case "account_type_asc":
							mapQuery[k] = " account_type ASC "
						case "corp_name_desc":
							mapQuery[k] = " corp_name DESC "
						case "corp_name_asc":
							mapQuery[k] = " corp_name ASC "
						case "account_status_desc":
							mapQuery[k] = " account_status DESC "
						case "account_status_asc":
							mapQuery[k] = " account_status ASC "
						case "country_desc":
							mapQuery[k] = " country DESC "
						case "country_asc":
							mapQuery[k] = " country ASC "
						default:
							mapQuery[k] = " date_registered ASC "
						}
					}
					continue

				}
			}
			// keeps record of all invalid key:value
			invalidValue = append(invalidValue, strings.ToLower(k))
			continue
		}

		if strings.ToLower(k) == "date_registered" || strings.ToLower(k) == "date_activated" && validators[strings.ToLower(k)] == 0 {
			validators[strings.ToLower(k)] = 2
		}

		continue
	}

	// exclude userID from query
	if hasIDParam {
		mapQuery["id"] = fmt.Sprintf(" (%s) AND id != UUID_TO_BIN('%s') ", mapQuery["id"], userID)
	} else {
		mapQuery["id"] = fmt.Sprintf(" id != UUID_TO_BIN('%s') ", userID)
	}

	res, err := s.repository.GetAll(ctx, mapQuery)

	return res, invalidValue, err
}

func (s *service) Login(ctx context.Context, login domain.Login) (*domain.JWT, error) {
	logger.WithField(ctx, "bir.user.login", login.Email)

	user, err := s.repository.GetByEmailWithPassword(ctx, login.Email)

	if user == nil || err != nil {
		return nil, interr.LoginCredentialsErr
	}

	passErr := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(login.Password))
	if passErr != nil {
		return nil, interr.LoginCredentialsErr
	}

	if !user.AccountStatus {
		return nil, interr.UserNotActiveErr
	}

	// Access Token
	expiresAt := time.Now().Add(time.Minute * time.Duration(s.loginExp))
	accessTokenString, _ := s.jwtParser.CreateAccessToken(user.ID, user.Role, expiresAt)

	// Refresh Token used to get new Access Token
	refreshExpiresAt := time.Now().Add(time.Minute * time.Duration(s.loginExp+1))
	if login.RememberMe {
		refreshExpiresAt = time.Now().Add(time.Minute * time.Duration(s.rememberExp))
	}
	refreshTokenString, _ := s.jwtParser.CreateRefreshToken(user.ID, login.RememberMe, refreshExpiresAt)

	return &domain.JWT{
		AccessToken:      accessTokenString,
		RefreshToken:     refreshTokenString,
		ExpiresAt:        expiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

func (s *service) GenerateAccessToken(ctx context.Context, token string) (*domain.JWT, error) {
	forgotPassClaims, err := s.jwtParser.ParseForgotPasswordToken(token)
	if err != nil {
		return nil, interr.InvalidToken
	}

	user, userErr := s.repository.GetByEmailWithPassword(ctx, forgotPassClaims.Email)
	if userErr != nil {
		return nil, interr.InvalidToken
	}

	if user.PasswordChangedDate.Valid && user.PasswordChangedDate.Time.Unix() > forgotPassClaims.IssuedAt {
		return nil, interr.InvalidToken
	}

	expiresAt := time.Now().Add(time.Minute * time.Duration(s.loginExp))
	accessTokenString, _ := s.jwtParser.CreateAccessToken(user.ID, user.Role, expiresAt)

	return &domain.JWT{
		AccessToken: accessTokenString,
		ExpiresAt:   expiresAt,
	}, nil
}

func (s *service) Refresh(ctx context.Context, refreshToken *jwtparser.RefreshTokenClaims, isAdmin bool) (*domain.JWT, error) {
	// nil check the tokens
	if refreshToken == nil {
		return nil, nil
	}

	user, err := s.repository.GetByID(ctx, refreshToken.ID)
	if err != nil {
		return nil, err
	}
	if !user.AccountStatus {
		return nil, errors.New("failed to refresh token, deactivated account")
	}

	// check role
	role, err := helper.NewRoleChecker(user.Role)
	if isAdmin && (!role.IsUserAdmin() || err != nil) {
		return nil, interr.UnauthorizeErr
	}

	// Create New Access Token
	expiresAt := time.Now().Add(time.Minute * time.Duration(s.loginExp))
	accessTokenString, _ := s.jwtParser.CreateAccessToken(user.ID, user.Role, expiresAt)

	// Refresh Token used to get new Access Token
	refreshExpiresAt := time.Now().Add(time.Minute * time.Duration(s.loginExp+1))
	if refreshToken.RememberMe {
		refreshExpiresAt = time.Now().Add(time.Minute * time.Duration(s.rememberExp))
	}
	refreshTokenString, _ := s.jwtParser.CreateRefreshToken(user.ID, refreshToken.RememberMe, refreshExpiresAt)

	return &domain.JWT{
		AccessToken:      accessTokenString,
		ExpiresAt:        expiresAt,
		RefreshToken:     refreshTokenString,
		RefreshExpiresAt: refreshExpiresAt,
	}, nil
}

func (s *service) GetActivationLink(ctx context.Context, email string) string {
	logger.WithField(ctx, "bir.user.activation_link", email)
	user, _ := s.repository.GetByEmailWithPassword(ctx, email)
	activationToken, _ := s.jwtParser.CreateActivationToken(user.ID)
	return s.frontendUrl + "/account/activate/" + activationToken
}

func (s *service) GetForgotPasswordLink(ctx context.Context, email string) (string, error) {
	user, err := s.repository.GetByEmailWithPassword(ctx, email)
	if err != nil || user == nil {
		return "", interr.NotFoundErr
	}
	forgotPasswordToken, _ := s.jwtParser.CreateForgotPasswordToken(user.Email)
	return s.frontendUrl + "/forgot_password/" + forgotPasswordToken, nil
}

func (s *service) ValidateForgotPassword(ctx context.Context, token string) error {
	forgotPassClaims, err := s.jwtParser.ParseForgotPasswordToken(token)
	if err != nil {
		return interr.InvalidToken
	}

	user, userErr := s.repository.GetByEmailWithPassword(ctx, forgotPassClaims.Email)
	if userErr != nil {
		return interr.InvalidToken
	}

	if user.PasswordChangedDate.Valid && user.PasswordChangedDate.Time.Unix() > forgotPassClaims.IssuedAt {
		return interr.InvalidToken
	}

	return nil
}

func (s *service) UpdatePassword(ctx context.Context, token string, password string) error {
	tokenErr := s.ValidateForgotPassword(ctx, token)
	if tokenErr != nil {
		return interr.InvalidToken
	}

	claims, _ := s.jwtParser.ParseForgotPasswordToken(token)

	bytePass := []byte(password)

	user, err := s.repository.GetByEmailWithPassword(ctx, claims.Email)
	if user == nil || err != nil {
		return interr.LoginCredentialsErr
	}

	passErr := bcrypt.CompareHashAndPassword([]byte(user.Password), bytePass)
	if passErr != nil {
		hashed, _ := bcrypt.GenerateFromPassword(bytePass, bcrypt.DefaultCost)
		return s.repository.UpdatePassword(ctx, claims.Email, string(hashed))
	}

	return fmt.Errorf("new password cannot be the same as the old password")
}

func (s *service) ActivateAccount(ctx context.Context, token string) error {
	activationClaims, err := s.jwtParser.ParseActivationToken(token)
	if err != nil {
		return interr.InvalidToken
	}

	user, userErr := s.repository.GetByID(ctx, activationClaims.ID)
	if userErr != nil || user == nil || user.AccountStatus { // user not found or account already activated
		return interr.InvalidToken
	}

	activationError := s.repository.Activate(ctx, activationClaims.ID)
	if activationError != nil {
		return interr.InvalidToken
	}

	return nil
}

// Register
func (s *service) Create(ctx context.Context, registration domain.Registration) (*domain.User, error) {
	logger.WithField(ctx, "registration", registration)

	newUUID, _ := uuid.NewUUID()
	registration.ID = newUUID
	registration.DateRegistered = time.Now()
	registration.DateActivated = pq.NullTime{}
	registration.AccountStatus = false

	// Hash password
	bytePass := []byte(registration.Password)
	password, _ := bcrypt.GenerateFromPassword(bytePass, bcrypt.DefaultCost)
	registration.Password = string(password)

	err := s.repository.Create(ctx, registration)

	if err != nil {
		return nil, err
	}

	user := &domain.User{}
	user.ID = registration.ID
	user.Email = registration.Email
	user.FirstName = registration.FirstName
	user.MiddleName = registration.MiddleName
	user.LastName = registration.LastName
	user.Address = registration.Address
	user.City = registration.City
	user.Country = registration.Country
	user.TIN = registration.TIN
	user.ContactNum = registration.ContactNum
	user.AccountStatus = registration.AccountStatus
	user.DateRegistered = registration.DateRegistered
	user.DateActivated = registration.DateActivated
	user.AccountType = registration.AccountType
	user.CorpName = registration.CorpName
	user.CorpAddress = registration.CorpAddress
	user.RDOCode = registration.RDOCode

	return user, nil
}

func (s *service) Update(ctx context.Context, u domain.User) (*domain.User, error) {
	logger.WithField(ctx, "u", u)

	err := s.repository.Update(ctx, u)

	if err != nil {
		return nil, err
	}

	user := &domain.User{}
	user.ID = u.ID
	user.Email = u.Email
	user.FirstName = u.FirstName
	user.MiddleName = u.MiddleName
	user.LastName = u.LastName
	user.Address = u.Address
	user.City = u.City
	user.Country = u.Country
	user.TIN = u.TIN
	user.ContactNum = u.ContactNum
	user.AccountType = u.AccountType
	user.CorpName = u.CorpName
	user.CorpAddress = u.CorpAddress
	user.RDOCode = u.RDOCode

	return user, nil
}

func (s *service) GetUserDeactivateLogs(ctx context.Context, authID, userID uuid.UUID, action string) ([]domain.ActivityLog, error) {
	logger.WithField(ctx, "bir.getUserLogs.id", userID)

	user, err := s.repository.GetByID(ctx, authID)

	if err != nil {
		return []domain.ActivityLog{}, interr.NotFoundErr
	}
	// check role
	role, err := helper.NewRoleChecker(user.Role)
	if !role.IsUserAdmin() || err != nil {
		return []domain.ActivityLog{}, interr.UnauthorizeErr
	}

	return s.repository.GetUserLogs(ctx, userID, "")
}

func (s *service) UpdateStatus(ctx context.Context, user domain.User, reason string, authID uuid.UUID) error {
	logger.WithField(ctx, "bir.updateUserStatus.id", user.ID)

	admin, err := s.repository.GetByID(ctx, authID)

	if err != nil {
		return interr.NotFoundErr
	}

	// check role
	role, err := helper.NewRoleChecker(admin.Role)
	if !role.IsUserAdmin() || err != nil {
		return interr.UnauthorizeErr
	}

	return s.repository.UpdateStatus(ctx, user, reason, *admin)
}

func (s *service) UpdateRole(ctx context.Context, user domain.User, reason string, authID uuid.UUID) error {
	logger.WithField(ctx, "bir.updateuserrole.id", user.ID)

	admin, err := s.repository.GetByID(ctx, authID)

	if err != nil {
		return interr.NotFoundErr
	}

	// check role
	role, err := helper.NewRoleChecker(admin.Role)
	if !role.IsUserAdmin() || err != nil {
		return interr.UnauthorizeErr
	}

	return s.repository.UpdateRole(ctx, user, reason, *admin)
}

func areDatesConsecutiveOrEqual(strTimes []string) (bool, bool) {
	var tFrom, tTo time.Time

	if len(strTimes) != 2 {
		return false, false
	}
	for _, dv := range strTimes {
		if len(dv) > 3 && strings.ToLower(dv[0:3]) == "fr:" {
			sDate := strings.Replace(strings.ToLower(dv), "fr:", "", 1)
			tDate, err := time.Parse("2006-01-02", sDate)
			if err != nil {
				return false, false
			}
			tFrom = tDate
		}
		if len(dv) > 3 && strings.ToLower(dv[0:3]) == "to:" {
			sDate := strings.Replace(strings.ToLower(dv), "to:", "", 1)
			tDate, err := time.Parse("2006-01-02", sDate)
			if err != nil {
				return false, false
			}
			tTo = tDate
		}
	}

	return tFrom.Before(tTo), tFrom.Equal(tTo)
}

package user

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"

	"github.com/aisalamdag23/clean-architecture-template/internal/domain"
	"github.com/aisalamdag23/clean-architecture-template/internal/domain/interr"
	"github.com/aisalamdag23/clean-architecture-template/internal/infrastructure/logger"
)

type (
	repository struct {
		db *sqlx.DB
	}

	activityLog struct {
		userID uuid.UUID
		log    string
		action string
	}
)

const constLimit = 20

// NewRepository constructor for User repository
func NewRepository(db *sqlx.DB) domain.UserRepository {
	return &repository{db: db}
}

// GetByID ...
func (r *repository) GetByID(ctx context.Context, transactionID uuid.UUID) (*domain.User, error) {
	query := `
	-- <operation>get_by_id</operation>
	-- <collection>user</collection>
	SELECT id, email, first_name, middle_name, last_name, address, city, country, tin, contact_num, account_status, date_registered, date_activated, account_type, corp_name, corp_address, rdo_code, role
	FROM users t
	WHERE t.id = UUID_TO_BIN(?)`

	var transaction domain.User
	err := r.db.GetContext(ctx, &transaction, query, transactionID.String())
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, interr.NotFoundErr
		}

		return nil, fmt.Errorf("failed to execute GetByID query: %w", err)
	}

	return &transaction, nil
}

func (r *repository) Activate(ctx context.Context, id uuid.UUID) error {
	query := `	UPDATE users SET
					account_status = ?, date_activated = ? 
				WHERE 
				    id = UUID_TO_BIN(?)`

	_, err := r.db.Exec(query, true, time.Now(), id)

	return err
}

func (r *repository) UpdatePassword(ctx context.Context, email string, password string) error {
	query := `	UPDATE users SET
					password = ?, password_changed_date = CURRENT_TIMESTAMP
				WHERE 
				    email = ?`

	_, err := r.db.Exec(query, password, email)

	return err
}

// GetByEmail ...
func (r *repository) GetByEmailWithPassword(ctx context.Context, email string) (*domain.UserWithPassword, error) {
	query := `
	-- <operation>get_by_email</operation>
	-- <collection>user</collection>
	SELECT *
	FROM users t
	WHERE t.email = ?`

	var user domain.UserWithPassword
	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, interr.NotFoundErr
		}
		return nil, fmt.Errorf("failed to execute GetByID query: %w", err)
	}

	return &user, nil
}

// GetAll ...
func (r *repository) GetAll(ctx context.Context, mapQuery map[string]string) (*domain.UsersList, error) {
	var where, pagination string
	var orderBy = " date_registered ASC "
	var limit = constLimit
	var offset = 0

	// where clause
	if len(mapQuery) > 0 {
		for k, v := range mapQuery {
			if strings.ToLower(k) == "sort" {
				orderBy = v
			} else {
				if len(where) > 0 {
					where += " AND "
				}
				where += "(" + v + ")"
			}
		}
	}

	if len(where) > 0 {
		where = " WHERE " + where
	}

	// limit and offset
	if v, existsLimit := mapQuery["limit"]; existsLimit {
		intL, _ := strconv.Atoi(v)
		limit = intL

	}
	pagination = fmt.Sprintf(" LIMIT %d ", limit)

	if v, existsPage := mapQuery["page"]; existsPage {
		intP, _ := strconv.Atoi(v)
		mult := intP - 1

		if mult < 0 {
			mult = 0
		}
		offset = limit * mult
	}
	pagination += fmt.Sprintf(" OFFSET %d ", offset)

	query := `
				-- <operation>get_all</operation>
				-- <collection>user</collection>
				SELECT 
					id, 
					email, 
					first_name, 
					middle_name, 
					last_name, 
					address, 
					city, 
					country, 
					tin, 
					contact_num, 
					rdo_code, 
					role,
					account_type, 
					corp_name, 
					corp_address, 
					account_status, 
					date_registered, 
					date_activated
				FROM 
					users ` + where + `
				ORDER BY ` + orderBy

	// first get all rows for total_rows field
	var totalRows int
	rows, err := r.db.QueryContext(ctx, "SELECT COUNT(id) AS total_rows FROM users "+where)
	if err != nil {
		return nil, fmt.Errorf("failed to execute GetAll query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		_ = rows.Scan(&totalRows)
	}

	// then query with the limit and offset
	query += " " + pagination

	var users []domain.User
	rows, err = r.db.QueryContext(ctx, query)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, interr.NotFoundErr
		}

		return nil, fmt.Errorf("failed to execute GetByID query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		user := domain.User{}
		err = rows.Scan(&user.ID,
			&user.Email,
			&user.FirstName,
			&user.MiddleName,
			&user.LastName,
			&user.Address,
			&user.City,
			&user.Country,
			&user.TIN,
			&user.ContactNum,
			&user.RDOCode,
			&user.Role,
			&user.AccountType,
			&user.CorpName,
			&user.CorpAddress,
			&user.AccountStatus,
			&user.DateRegistered,
			&user.DateActivated)

		if err != nil {
			return nil, errors.Wrap(err, "failed to scan a transaction")
		}
		users = append(users, user)
	}
	// so as not to return null or nil
	if users == nil {
		users = []domain.User{}
	}

	// format into struct
	list := domain.UsersList{
		Users:      users,
		TotalRows:  totalRows,
		TotalPages: 1,
	}
	// ceiling
	totalPages := totalRows / limit
	if totalPages > 1 {
		list.TotalPages = totalPages
	}

	return &list, err
}

// Create inserts new record at the user table
func (r *repository) Create(ctx context.Context, registration domain.Registration) error {
	query := `	INSERT INTO users
					(id, email, password, first_name, middle_name, last_name, address, city, country, tin, contact_num, account_status, date_registered, date_activated, account_type, corp_name, corp_address, rdo_code) 
				VALUES 
				    (UUID_TO_BIN(?, true), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := r.db.Exec(query,
		registration.ID,
		registration.Email,
		registration.Password,
		registration.FirstName,
		registration.MiddleName,
		registration.LastName,
		registration.Address,
		registration.City,
		registration.Country,
		registration.TIN,
		registration.ContactNum,
		registration.AccountStatus,
		registration.DateRegistered,
		registration.DateActivated,
		registration.AccountType,
		registration.CorpName,
		registration.CorpAddress,
		registration.RDOCode)

	if err == nil {
		log, err := json.Marshal(registration)

		if err == nil {
			_ = r.createLog(ctx, activityLog{
				userID: registration.ID,
				log:    string(log),
				action: "CREATE_USER",
			})
		} else {
			logger.WithField(ctx, "users.createLog.jsonMarshal.error", err.Error())
		}
	}

	return err
}

/**
 * Updates a user account
 * Does not allow you to update email, password, account status, date registered and date activated
 */
func (r *repository) Update(ctx context.Context, user domain.User) error {
	query := `	UPDATE users SET
					first_name = ?, middle_name = ?, last_name = ?, address = ?, city = ?, country = ?, tin = ?, contact_num = ?, account_type = ?, corp_name = ?, corp_address = ?, rdo_code = ? 
				WHERE 
				    id = UUID_TO_BIN(?)`

	_, err := r.db.Exec(query,
		user.FirstName,
		user.MiddleName,
		user.LastName,
		user.Address,
		user.City,
		user.Country,
		user.TIN,
		user.ContactNum,
		user.AccountType,
		user.CorpName,
		user.CorpAddress,
		user.RDOCode,
		user.ID)

	if err == nil {
		log, err := json.Marshal(user)

		if err == nil {
			_ = r.createLog(ctx, activityLog{
				userID: user.ID,
				log:    string(log),
				action: "UPDATE_USER",
			})
		} else {
			logger.WithField(ctx, "users.createLog.jsonMarshal.error", err.Error())
		}
	}

	return err
}

// UpdateStatus deactivates or activates existing user
func (r *repository) UpdateStatus(ctx context.Context, user domain.User, reason string, admin domain.User) error {
	query := `	
				UPDATE users 
				SET
					account_status = ?
				WHERE 
				    id = UUID_TO_BIN(?)`

	_, err := r.db.Exec(query,
		user.AccountStatus,
		user.ID)

	if err == nil {
		insLog := domain.DeactivateLog{
			UpdatedBy: admin.ID,
			AdminName: admin.LastName + ", " + admin.FirstName,
		}

		if reason != "" && !user.AccountStatus {
			insLog.Reason = reason
		}

		log, err := json.Marshal(insLog)

		action := "ACTIVATE_USER"
		if !user.AccountStatus {
			action = "DEACTIVATE_USER"
		}

		if err == nil {
			_ = r.createLog(ctx, activityLog{
				userID: user.ID,
				log:    string(log),
				action: action,
			})
		} else {
			logger.WithField(ctx, "users.createLog.jsonMarshal.error", err.Error())
		}
	}

	return err
}

// UpdateRole change user's role
func (r *repository) UpdateRole(ctx context.Context, user domain.User, reason string, admin domain.User) error {
	query := `	
				UPDATE users 
				SET
					role = ?
				WHERE 
				    id = UUID_TO_BIN(?)`

	_, err := r.db.Exec(query,
		strings.ToUpper(user.Role),
		user.ID)

	if err == nil {
		insLog := domain.DeactivateLog{
			UpdatedBy: admin.ID,
			AdminName: admin.LastName + ", " + admin.FirstName,
		}

		if reason != "" {
			insLog.Reason = reason
		}

		log, err := json.Marshal(insLog)

		action := "UPDATE_USER_ROLE"

		if err == nil {
			_ = r.createLog(ctx, activityLog{
				userID: user.ID,
				log:    string(log),
				action: action,
			})
		} else {
			logger.WithField(ctx, "users.createLog.jsonMarshal.error", err.Error())
		}
	}

	return err
}

func (r *repository) createLog(ctx context.Context, activity activityLog) error {
	query := `
				INSERT INTO activity_logs
					(user_id, log, action, created_at)
				VALUES
					(UUID_TO_BIN(?, true), ?, ?, NOW())`

	_, err := r.db.Exec(query, activity.userID, activity.log, activity.action)

	if err != nil {
		logger.WithField(ctx, "users.createLog.error", err.Error())
	}

	// return err
	return err
}

func (r *repository) GetUserLogs(ctx context.Context, userID uuid.UUID, action string) ([]domain.ActivityLog, error) {
	query := `
				SELECT 
					* 
				FROM activity_logs 
				WHERE 
					user_id = UUID_TO_BIN(?, true)`

	if action != "" {
		query += ` AND action = "` + action + `"`
	} else {
		query += ` AND action IN ("DEACTIVATE_USER", "UPDATE_USER_ROLE", "ACTIVATE_USER") `
	}
	query += ` ORDER BY created_at DESC`

	var logs []domain.ActivityLog
	rows, err := r.db.QueryContext(ctx, query, userID.String())

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, interr.NotFoundErr
		}

		return nil, fmt.Errorf("failed to execute GetByID query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		log := domain.ActivityLog{}
		err = rows.Scan(&log.ID, &log.UserID, &log.Log, &log.Action, &log.CreatedAt)
		if err != nil {
			return nil, errors.Wrap(err, "failed to scan logs")
		}

		logs = append(logs, log)
	}

	return logs, nil
}

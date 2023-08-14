package v1

import (
	"encoding/json"
	"fmt"
	"net/http"

	"gopkg.in/go-playground/validator.v9"

	"github.com/google/uuid"
	"github.com/gorilla/mux"

	"github.com/aisalamdag23/clean-architecture-template/internal/domain"
	"github.com/aisalamdag23/clean-architecture-template/internal/domain/interr"
	"github.com/aisalamdag23/clean-architecture-template/internal/usecase/email"
)

type Handler struct {
	service      domain.UserService
	emailService *email.Service
}

type Result struct {
	Title  string `json:"title"`
	Status int    `json:"status"`
	Detail string `json:"detail"`
}

func NewServer(service domain.UserService, emailService *email.Service) *Handler {
	return &Handler{service, emailService}
}

func (h *Handler) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/users", h.CreateHandler).Methods("POST")
	router.HandleFunc("/users/{id}", h.GetByIDHandler).Methods("GET")
}

func (h *Handler) GetByIDHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := uuid.Parse(vars["id"])
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Invalid User ID"))
		return
	}

	txn, err := h.service.GetByID(r.Context(), id)
	if err != nil {
		if err == interr.NotFoundErr {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(fmt.Sprintf("ID not found %x", id)))
			return
		} else {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("Internal error occurred"))
			return
		}
	}

	resp, err := json.Marshal(txn)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Data marshalling error"))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func (h *Handler) CreateHandler(w http.ResponseWriter, r *http.Request) {
	var registration domain.Registration

	v := validator.New()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	err := json.NewDecoder(r.Body).Decode(&registration)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(Result{
			Title:  "Bad Request",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		})
		return
	}

	// validate request body
	err = v.Struct(registration)

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(Result{
			Title:  "Bad Request",
			Status: http.StatusBadRequest,
			Detail: err.Error(),
		})
		return
	}

	user, err := h.service.Create(r.Context(), registration)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(Result{
			Title:  "Internal Server Error",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
		})
		return
	}

	activationLink := h.service.GetActivationLink(r.Context(), user.Email)

	h.emailService.SendActivationEmail(r.Context(), user.Email, activationLink)

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(user)
}

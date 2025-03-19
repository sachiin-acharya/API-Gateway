// internal/handlers/auth.go

package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/your-org/api-gateway/intenal/services"
	"github.com/your-org/api-gateway/internal/config"
	"github.com/your-org/api-gateway/pkg/logging"
)

type AuthHandler struct {
	authService services.AuthService
	cfg         *config.Config
	logger      *logging.Logger
}

func NewAuthHandler(authService services.AuthService, cfg *config.Config, logger *logging.Logger) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		cfg:         cfg,
		logger:      logger,
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var loginRequest models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.authService.Authenticate(loginRequest.Username, loginRequest.Password)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	accessToken, refreshToken, err := h.generateTokens(user)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}

	response := models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: models.UserResponse{
			UUID:      user.UUID,
			Username:  user.Username,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var registerRequest models.registerRequest
	if err := json.NewDecoder(r.Body).Decode(&registerRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	user, err := h.authService.Register(registerRequest)
	if err != nil {
		http.Error(w, "Registration failed: "+err.Error(), http.StatusBadRequest)
		return
	}
	accessToken, refreshToken, err := h.generateTokens(user)
	if err != nil {
		http.Error(w, "Failed to generate tokens", http.StatusInternalServerError)
		return
	}
	response := models.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User: models.UserResponse{
			UUID:      user.UUID,
			Username:  user.Username,
			Email:     user.Email,
			FirstName: user.FirstName,
			LastName:  user.LastName,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

func (h *AuthHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var refreshRequest models.RefreshTokenRequest

	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	token, err := jwt.Parse(refreshRequest.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(h.cfg.Auth.JWTSecret), nil
	})
}

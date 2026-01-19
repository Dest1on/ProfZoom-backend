package middleware

import (
	"context"
	"net/http"
	"strings"

	"profzom/internal/common"
	"profzom/internal/domain/user"
	"profzom/internal/http/response"
	"profzom/internal/security"
)

type contextKey string

const (
	ContextUserIDKey contextKey = "user_id"
	ContextRolesKey  contextKey = "roles"
	ContextRoleKey   contextKey = "role"
)

type AuthMiddleware struct {
	jwt *security.JWTProvider
}

func NewAuthMiddleware(jwt *security.JWTProvider) *AuthMiddleware {
	return &AuthMiddleware{jwt: jwt}
}

func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			response.Error(w, common.NewError(common.CodeUnauthorized, "missing authorization header", nil))
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			response.Error(w, common.NewError(common.CodeUnauthorized, "invalid authorization header", nil))
			return
		}
		claims, err := m.jwt.Parse(parts[1])
		if err != nil {
			response.Error(w, common.NewError(common.CodeUnauthorized, "invalid token", err))
			return
		}
		userID, err := common.ParseUUID(claims.UserID)
		if err != nil {
			response.Error(w, common.NewError(common.CodeUnauthorized, "invalid user id", err))
			return
		}
		roles := make([]user.Role, 0, len(claims.Roles))
		for _, role := range claims.Roles {
			roles = append(roles, user.Role(role))
		}
		activeRole := strings.ToLower(strings.TrimSpace(claims.Role))
		if activeRole == "" && len(roles) == 1 {
			activeRole = strings.ToLower(string(roles[0]))
		}
		if activeRole != "" {
			found := false
			for _, role := range roles {
				if strings.ToLower(string(role)) == activeRole {
					found = true
					break
				}
			}
			if !found {
				activeRole = ""
			}
		}
		ctx := context.WithValue(r.Context(), ContextUserIDKey, userID)
		ctx = context.WithValue(ctx, ContextRolesKey, roles)
		ctx = context.WithValue(ctx, ContextRoleKey, user.Role(activeRole))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func RequireRole(role user.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			activeRole, ok := r.Context().Value(ContextRoleKey).(user.Role)
			if !ok {
				response.Error(w, common.NewError(common.CodeForbidden, "role not found", nil))
				return
			}
			if activeRole == "" {
				response.Error(w, common.NewError(common.CodeForbidden, "role not selected", nil))
				return
			}
			if activeRole != role {
				response.Error(w, common.NewError(common.CodeForbidden, "insufficient role", nil))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func UserIDFromContext(ctx context.Context) (common.UUID, bool) {
	id, ok := ctx.Value(ContextUserIDKey).(common.UUID)
	return id, ok
}

func ActiveRoleFromContext(ctx context.Context) (user.Role, bool) {
	role, ok := ctx.Value(ContextRoleKey).(user.Role)
	return role, ok
}

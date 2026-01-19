package http

import (
	"net/http"
	"strings"
	"time"

	"profzom/internal/domain/user"
	"profzom/internal/http/handlers"
	"profzom/internal/http/metrics"
	httpmw "profzom/internal/http/middleware"
)

type RouterDependencies struct {
	AuthHandler        *handlers.AuthHandler
	UserHandler        *handlers.UserHandler
	ProfileHandler     *handlers.ProfileHandler
	VacancyHandler     *handlers.VacancyHandler
	ApplicationHandler *handlers.ApplicationHandler
	MessageHandler     *handlers.MessageHandler
	MetricsHandler     *handlers.MetricsHandler
	AuthMiddleware     *httpmw.AuthMiddleware
	Metrics            *metrics.Collector
	RequestTimeout     time.Duration
}

type Router struct {
	deps RouterDependencies
}

const maxBodyBytes = 1 << 20

func NewRouter(deps RouterDependencies) http.Handler {
	return &Router{deps: deps}
}

func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	handler := httpmw.Chain(r.baseHandler(), httpmw.RequestID, httpmw.Logging, httpmw.BodyLimit(maxBodyBytes), httpmw.Recover, httpmw.Metrics(r.deps.Metrics), httpmw.Timeout(r.deps.RequestTimeout))
	handler.ServeHTTP(w, req)
}

func (r *Router) baseHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path

		switch {
		case req.Method == http.MethodGet && path == "/health":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
			return
		case req.Method == http.MethodGet && path == "/metrics":
			r.deps.MetricsHandler.Get(w, req)
			return
		case req.Method == http.MethodPost && path == "/auth/request-code":
			r.deps.AuthHandler.RequestOTPByTelegram(w, req)
			return
		case req.Method == http.MethodPost && path == "/auth/register":
			r.deps.AuthHandler.Register(w, req)
			return
		case req.Method == http.MethodPost && path == "/auth/refresh":
			r.deps.AuthHandler.Refresh(w, req)
			return
		case req.Method == http.MethodPost && path == "/auth/switch-role":
			r.deps.AuthHandler.SwitchRole(w, req)
			return
		case req.Method == http.MethodPost && path == "/auth/verify-code":
			r.deps.AuthHandler.VerifyOTP(w, req)
			return
		case req.Method == http.MethodPost && path == "/auth/logout":
			r.deps.AuthHandler.Logout(w, req)
			return
		case req.Method == http.MethodGet && path == "/vacancies":
			r.deps.VacancyHandler.ListPublished(w, req)
			return
		case req.Method == http.MethodGet && strings.HasPrefix(path, "/vacancies/"):
			r.deps.VacancyHandler.Get(w, req)
			return
		}

		if strings.HasPrefix(path, "/companies") || strings.HasPrefix(path, "/students") || strings.HasPrefix(path, "/users") || strings.HasPrefix(path, "/vacancies") || strings.HasPrefix(path, "/applications") {
			protected := r.deps.AuthMiddleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				r.handleProtected(w, req)
			}))
			protected.ServeHTTP(w, req)
			return
		}

		http.NotFound(w, req)
	})
}

func (r *Router) handleProtected(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path

	switch {
	case req.Method == http.MethodPatch && path == "/users/role":
		r.deps.UserHandler.SetRole(w, req)
		return
	case req.Method == http.MethodGet && path == "/students/profile":
		httpmw.RequireRole(user.RoleStudent)(http.HandlerFunc(r.deps.ProfileHandler.GetStudent)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPost && path == "/students/profile":
		httpmw.RequireRole(user.RoleStudent)(http.HandlerFunc(r.deps.ProfileHandler.UpsertStudent)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPut && path == "/students/profile":
		httpmw.RequireRole(user.RoleStudent)(http.HandlerFunc(r.deps.ProfileHandler.UpsertStudent)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodGet && path == "/companies/profile":
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.ProfileHandler.GetCompany)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPost && path == "/companies/profile":
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.ProfileHandler.UpsertCompany)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPut && path == "/companies/profile":
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.ProfileHandler.UpsertCompany)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodGet && path == "/students/vacancies/recommended":
		httpmw.RequireRole(user.RoleStudent)(http.HandlerFunc(r.deps.VacancyHandler.ListRecommended)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodGet && path == "/companies/vacancies":
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.VacancyHandler.ListByCompany)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodGet && strings.HasPrefix(path, "/companies/vacancies/"):
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.VacancyHandler.GetByCompany)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPost && path == "/vacancies":
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.VacancyHandler.Create)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPatch && strings.HasPrefix(path, "/vacancies/") && !strings.HasSuffix(path, "/status"):
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.VacancyHandler.Update)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPatch && strings.HasPrefix(path, "/vacancies/") && strings.HasSuffix(path, "/status"):
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.VacancyHandler.UpdateStatus)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPatch && strings.HasPrefix(path, "/applications/") && strings.HasSuffix(path, "/status"):
		httpmw.RequireRole(user.RoleCompany)(http.HandlerFunc(r.deps.ApplicationHandler.UpdateStatus)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodPost && path == "/applications":
		httpmw.RequireRole(user.RoleStudent)(http.HandlerFunc(r.deps.ApplicationHandler.Apply)).ServeHTTP(w, req)
		return
	case req.Method == http.MethodGet && path == "/applications":
		r.deps.ApplicationHandler.List(w, req)
		return
	case req.Method == http.MethodPost && strings.HasSuffix(path, "/messages") && strings.HasPrefix(path, "/applications/"):
		r.deps.MessageHandler.Send(w, req)
		return
	case req.Method == http.MethodGet && strings.HasSuffix(path, "/messages") && strings.HasPrefix(path, "/applications/"):
		r.deps.MessageHandler.List(w, req)
		return
	}

	http.NotFound(w, req)
}

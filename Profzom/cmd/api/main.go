package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"profzom/internal/app"
	"profzom/internal/config"
	"profzom/internal/database"
	apphttp "profzom/internal/http"
	"profzom/internal/http/handlers"
	"profzom/internal/http/metrics"
	httpmw "profzom/internal/http/middleware"
	"profzom/internal/http/response"
	"profzom/internal/integration/otpbot"
	"profzom/internal/observability"
	"profzom/internal/repository/postgres"
	"profzom/internal/security"
)

func main() {
	cfg := config.Load()
	logger := observability.NewLogger()
	db := database.NewPostgres(database.PostgresConfig{
		DSN:             cfg.PostgresDSN,
		MaxOpenConns:    cfg.DBMaxOpenConns,
		MaxIdleConns:    cfg.DBMaxIdleConns,
		ConnMaxIdle:     cfg.DBConnMaxIdle,
		ConnMaxLifetime: cfg.DBConnMaxLife,
	})
	defer db.Close()

	userRepo := postgres.NewUserRepository(db)
	otpRepo := postgres.NewOTPRepository(db)
	refreshRepo := postgres.NewRefreshTokenRepository(db)
	analyticsRepo := postgres.NewAnalyticsRepository(db)
	telegramLinkRepo := postgres.NewTelegramLinkRepository(db)
	studentRepo := postgres.NewStudentProfileRepository(db)
	companyRepo := postgres.NewCompanyProfileRepository(db)
	vacancyRepo := postgres.NewVacancyRepository(db)
	applicationRepo := postgres.NewApplicationRepository(db)
	messageRepo := postgres.NewMessageRepository(db)

	jwtProvider := security.NewJWTProvider(cfg.JWTSecret)
	otpBotClient := otpbot.NewClient(cfg.OTPBotBaseURL, cfg.OTPBotInternalKey, &http.Client{Timeout: 5 * time.Second})

	authService := app.NewAuthServiceWithTelegramLinks(userRepo, otpRepo, refreshRepo, analyticsRepo, jwtProvider, otpBotClient, telegramLinkRepo, logger, cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.OTPTTL)
	userService := app.NewUserService(userRepo, analyticsRepo)
	profileService := app.NewProfileService(studentRepo, companyRepo, analyticsRepo)
	vacancyService := app.NewVacancyService(vacancyRepo, companyRepo, analyticsRepo)
	applicationService := app.NewApplicationService(applicationRepo, vacancyRepo, studentRepo, analyticsRepo)
	messageService := app.NewMessageService(messageRepo, applicationRepo, vacancyRepo, analyticsRepo)

	rateLimiter := httpmw.NewRateLimiter()
	authHandler := handlers.NewAuthHandler(authService, rateLimiter, cfg.OTPBotTelegramUsername, cfg.OTPBotInternalKey)
	userHandler := handlers.NewUserHandler(userService)
	profileHandler := handlers.NewProfileHandler(profileService)
	vacancyHandler := handlers.NewVacancyHandler(vacancyService)
	applicationHandler := handlers.NewApplicationHandler(applicationService, rateLimiter)
	messageHandler := handlers.NewMessageHandler(messageService, rateLimiter)
	middleware := httpmw.NewAuthMiddleware(jwtProvider)

	collector := metrics.NewCollector()
	response.SetErrorCollector(collector)

	router := apphttp.NewRouter(apphttp.RouterDependencies{
		AuthHandler:        authHandler,
		UserHandler:        userHandler,
		ProfileHandler:     profileHandler,
		VacancyHandler:     vacancyHandler,
		ApplicationHandler: applicationHandler,
		MessageHandler:     messageHandler,
		AuthMiddleware:     middleware,
		MetricsHandler:     handlers.NewMetricsHandler(collector),
		Metrics:            collector,
		RequestTimeout:     cfg.RequestTimeout,
	})
	server := &http.Server{
		Addr:         ":" + cfg.HTTPPort,
		Handler:      router,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		logger.Info("API started on :" + cfg.HTTPPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	<-quit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
}

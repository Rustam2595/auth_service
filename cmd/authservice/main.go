package main

import (
	"auth_service/internal/logger"
	"auth_service/internal/server"
	"cmp"
	"flag"
	"fmt"
	"google.golang.org/grpc"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"net"
	"os"
)

// gorm
const (
	defaultDbHost = "127.0.0.1"
	defaultDbPort = "5432"
	defaultDbUser = "ru"
	defaultDbPass = "2595"
	defaultDbName = "ru_DB"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug logging level")
	flag.Parse()
	zLog := logger.Get(*debug)
	zLog.Info().Msg("Starting auth service")

	dbUser := cmp.Or(os.Getenv("DB_USER"), defaultDbUser)
	dbPass := cmp.Or(os.Getenv("DB_PASS"), defaultDbPass)
	dbHost := cmp.Or(os.Getenv("DB_HOST"), defaultDbHost)
	dbName := cmp.Or(os.Getenv("DB_NAME"), defaultDbName)
	dbPort := cmp.Or(os.Getenv("DB_PORT"), defaultDbPort)
	dsn := fmt.Sprintf("host=%s user=%s dbname=%s sslmode=disable password=%s port=%s",
		dbHost, dbUser, dbName, dbPass, dbPort)

	zLog.Debug().Str("dsn", dsn).Msg("connect to db")

	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  dsn,
		PreferSimpleProtocol: true,
	}))
	if err != nil {
		zLog.Fatal().Err(err).Msg("failed to connect to db")
	}
	grpcServer := grpc.NewServer()
	server.RegisterAuthService(grpcServer, db)
	// Слушаем порт
	listener, err := net.Listen("tcp", ":8081")
	if err != nil {
		zLog.Fatal().Err(err).Msg("failed to listen")
	}
	// Запускаем сервер
	if err := grpcServer.Serve(listener); err != nil {
		zLog.Fatal().Err(err).Msg("failed to serve")
	}
}

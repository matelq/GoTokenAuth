package database

import (
	"context"
	pgx "github.com/jackc/pgx/v5/pgxpool"
)

var dbUrl string

func Init(connectionString string) error {
	dbUrl = connectionString
	dbpool, err := pgx.New(context.Background(), dbUrl)

	if err != nil {
		return err
	}
	defer dbpool.Close()

	return nil
}

func GetDbPool() (*pgx.Pool, error) {
	dbpool, err := pgx.New(context.Background(), dbUrl)
	if err != nil {
		return nil, err
	}
	return dbpool, nil
}

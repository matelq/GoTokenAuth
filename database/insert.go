package database

import (
	"context"
)

func InsertRefreshTokenHash(refreshHash string) error {
	pool, err := GetDbPool()
	if err != nil {
		return err
	}
	defer pool.Close()

	_, err = pool.Exec(context.Background(),
		`
		INSERT INTO public.refresh_tokens(token_hash) VALUES ($1);
		`,
		refreshHash)
	return err
}

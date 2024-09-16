package database

import (
	"context"
)

func DeleteRefreshHash(refreshHash string) error {
	pool, err := GetDbPool()
	if err != nil {
		return err
	}
	defer pool.Close()

	query := `DELETE FROM public.refresh_tokens WHERE token_hash = $1;`
	_, err = pool.Exec(context.Background(), query, refreshHash)

	return err
}

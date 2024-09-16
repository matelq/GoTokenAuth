package database

import (
	"context"
	"fmt"
	"time"
)

// Returns hash only if db contains it (otherwise it is not valid)
func SelectRefreshTokenHash(refreshHash string) (string, error) {
	pool, err := GetDbPool()
	if err != nil {
		return "", err
	}
	defer pool.Close()

	var dbRefreshHash string
	err = pool.QueryRow(context.Background(),
		`
		SELECT token_hash FROM public.refresh_tokens WHERE token_hash = $1
		`,
		refreshHash).
		Scan(&dbRefreshHash)

	if err != nil {
		return "", err
	}

	return refreshHash, nil
}

func SelectViableRefreshTokens(issuedAt time.Time) ([]string, error) {
	pool, err := GetDbPool()
	if err != nil {
		return nil, err
	}
	var refreshHashes []string
	defer pool.Close()
	rows, err := pool.Query(context.Background(), `
        SELECT token_hash 
		FROM public.refresh_tokens 
		WHERE created BETWEEN $1 AND CURRENT_TIMESTAMP
		`,
		issuedAt)

	if err != nil {
		return nil, err
	}
	defer rows.Close()
	
	for rows.Next() {
		var singleHash string
		err := rows.Scan(&singleHash)
		if err != nil {
			return refreshHashes, err
		}
		refreshHashes = append(refreshHashes, singleHash)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(refreshHashes) == 0 {
		return nil, fmt.Errorf("There's no viable hashes")
	}

	return refreshHashes, nil
}

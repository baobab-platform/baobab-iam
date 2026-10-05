package federation

import (
	"database/sql"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func pgxTestPool(dsn string) (*sql.DB, error) {
	c, e := pgx.ParseConfig(dsn)
	if e != nil {
		return nil, e
	}
	return stdlib.OpenDB(*c), nil
}

package database

import (
	"go.mau.fi/util/dbutil"
)

type Database struct {
	*dbutil.Database
}

func New(db *dbutil.Database) *Database {
	return &Database{
		Database: db,
	}
}

// Package schema holds the SQL files that build the AOS database.
// Files are applied in name order and never edited after release: a
// change to the schema is a new file.
package schema

import "embed"

//go:embed *.sql
var FS embed.FS

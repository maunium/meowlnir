package database

import (
	"context"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/id"
)

const (
	getSignatureQuery = `
		SELECT event_id, signature, created_at FROM policy_server_signature WHERE event_id=$1;
	`
	putSignatureQuery = `
		INSERT INTO policy_server_signature (event_id, signature, created_at) VALUES ($1, $2, $3)
		ON CONFLICT (event_id) DO UPDATE
			SET signature=excluded.signature, created_at=excluded.created_at
			WHERE policy_server_signature.signature IS NULL
	`
)

type PSSignatureQuery struct {
	*dbutil.QueryHelper[*PSSignature]
}

func (psq *PSSignatureQuery) Get(ctx context.Context, eventID id.EventID) (*PSSignature, error) {
	return psq.QueryOne(ctx, getSignatureQuery, eventID)
}

func (psq *PSSignatureQuery) Put(ctx context.Context, sig *PSSignature) error {
	return psq.Exec(ctx, putSignatureQuery, sig.sqlVariables()...)
}

type PSSignature struct {
	EventID   id.EventID
	Signature string
	CreatedAt jsontime.UnixMilli
}

func (ps *PSSignature) Scan(row dbutil.Scannable) (*PSSignature, error) {
	return dbutil.ValueOrErr(ps, row.Scan(&ps.EventID, &ps.Signature, &ps.CreatedAt))
}

func (ps *PSSignature) sqlVariables() []any {
	return []any{ps.EventID, ps.Signature, ps.CreatedAt}
}

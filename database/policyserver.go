package database

import (
	"context"
	"fmt"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/lib/pq"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/synapsedb"
)

const (
	getSignatureQuery = `
		SELECT event_id, signature, created_at FROM policy_server_signature WHERE event_id=$1;
	`
	putSignatureQuery = `
		INSERT INTO policy_server_signature (event_id, signature, created_at) VALUES ($1, $2, $3)
		ON CONFLICT (event_id) DO UPDATE
			SET signature=excluded.signature, created_at=excluded.created_at
			WHERE policy_server_signature.signature=''
	`
)

type PSSignatureQuery struct {
	*dbutil.QueryHelper[*PSSignature]
	cache *lru.Cache[id.EventID, *PSSignature]
}

func (psq *PSSignatureQuery) Get(ctx context.Context, eventID id.EventID) (val *PSSignature, err error) {
	var ok bool
	val, ok = psq.cache.Get(eventID)
	if ok {
		return
	}
	val, err = psq.QueryOne(ctx, getSignatureQuery, eventID)
	if err == nil {
		psq.cache.Add(eventID, val)
	}
	return
}

func (psq *PSSignatureQuery) Put(ctx context.Context, sig *PSSignature) error {
	psq.cache.Add(sig.EventID, sig)
	return psq.Exec(ctx, putSignatureQuery, sig.sqlVariables()...)
}

var signatureMassInsertBuilder = dbutil.NewMassInsertBuilder[*PSSignature, [1]any](`
	INSERT INTO policy_server_signature (event_id, signature, created_at) VALUES ($1, $2, $3)
	ON CONFLICT (event_id) DO NOTHING
`, "($%d, $%d, $1)")

func (psq *PSSignatureQuery) PutMany(ctx context.Context, sigs []*PSSignature) error {
	query, values := signatureMassInsertBuilder.Build([1]any{jsontime.UnixMilliNow()}, sigs)
	return psq.Exec(ctx, query, values...)
}

var scanEventID = dbutil.ConvertRowFn[id.EventID](dbutil.ScanSingleColumn[id.EventID])

func castMapKeysToString(source map[id.EventID]*synapsedb.OldEvent) []string {
	result := make([]string, len(source))
	i := 0
	for key := range source {
		result[i] = string(key)
		i++
	}
	return result
}

func castMapKeysToAny(source map[id.EventID]*synapsedb.OldEvent) []any {
	result := make([]any, len(source))
	i := 0
	for key := range source {
		result[i] = any(key)
		i++
	}
	return result
}

func (psq *PSSignatureQuery) FilterEventsToPreSign(ctx context.Context, events map[id.EventID]*synapsedb.OldEvent) error {
	var query string
	var values []any
	if psq.GetDB().Dialect == dbutil.Postgres {
		query = "SELECT event_id FROM policy_server_signature WHERE event_id = ANY($1)"
		values = []any{pq.Array(castMapKeysToString(events))}
	} else {
		placeholders := strings.Repeat("?,", len(events))
		placeholders = strings.TrimSuffix(placeholders, ",")
		query = fmt.Sprintf("SELECT event_id FROM policy_server_signature WHERE event_id IN (%s)", placeholders)
		values = castMapKeysToAny(events)
	}
	return scanEventID.NewRowIter(psq.GetDB().Query(ctx, query, values...)).Iter(func(eventID id.EventID) (bool, error) {
		delete(events, eventID)
		return true, nil
	})
}

type PSSignature struct {
	EventID   id.EventID
	Signature string
	CreatedAt jsontime.UnixMilli
}

func (ps *PSSignature) GetMassInsertValues() [2]any {
	return [2]any{ps.EventID, ps.Signature}
}

func (ps *PSSignature) Scan(row dbutil.Scannable) (*PSSignature, error) {
	return dbutil.ValueOrErr(ps, row.Scan(&ps.EventID, &ps.Signature, &ps.CreatedAt))
}

func (ps *PSSignature) sqlVariables() []any {
	return []any{ps.EventID, ps.Signature, ps.CreatedAt}
}

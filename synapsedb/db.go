package synapsedb

import (
	"context"

	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exslices"
	"maunium.net/go/mautrix/id"
)

type SynapseDB struct {
	DB *dbutil.Database
}

const PreferredVersion = 86

func (s *SynapseDB) CheckVersion(ctx context.Context) error {
	var current, compat int
	err := s.DB.QueryRow(ctx, "SELECT version FROM schema_version").Scan(&current)
	if err != nil {
		return err
	}
	err = s.DB.QueryRow(ctx, "SELECT compat_version FROM schema_compat_version").Scan(&compat)
	if err != nil {
		return err
	}
	if current < PreferredVersion {
		zerolog.Ctx(ctx).Warn().
			Int("preferred_version", PreferredVersion).
			Int("current_version", current).
			Int("current_compat_version", compat).
			Msg("Synapse database schema is older than expected")
	} else if compat > PreferredVersion {
		zerolog.Ctx(ctx).Warn().
			Int("preferred_version", PreferredVersion).
			Int("current_version", current).
			Int("current_compat_version", compat).
			Msg("Synapse database schema is newer than expected")
	}
	return nil
}

const getUnredactedEventsBySenderInRoomQuery = `
	SELECT events.room_id, events.event_id
	FROM events
	LEFT JOIN redactions ON events.event_id=redactions.redacts
	WHERE events.sender = $1 AND events.room_id = ANY($2) AND redactions.redacts IS NULL
`

type roomEventTuple struct {
	RoomID  id.RoomID
	EventID id.EventID
}

var scanRoomEventTuple = dbutil.ConvertRowFn[roomEventTuple](func(row dbutil.Scannable) (t roomEventTuple, err error) {
	err = row.Scan(&t.RoomID, &t.EventID)
	return
})

func (s *SynapseDB) GetEventsToRedact(ctx context.Context, sender id.UserID, inRooms []id.RoomID) (map[id.RoomID][]id.EventID, error) {
	output := make(map[id.RoomID][]id.EventID)
	err := scanRoomEventTuple.NewRowIter(
		s.DB.Query(ctx, getUnredactedEventsBySenderInRoomQuery, sender, pq.Array(exslices.CastToString[string](inRooms))),
	).Iter(func(tuple roomEventTuple) (bool, error) {
		output[tuple.RoomID] = append(output[tuple.RoomID], tuple.EventID)
		return true, nil
	})
	return output, err
}

func (s *SynapseDB) Close() error {
	return s.DB.Close()
}

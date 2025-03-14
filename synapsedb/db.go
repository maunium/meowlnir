package synapsedb

import (
	"context"
	"time"

	"github.com/lib/pq"
	"github.com/rs/zerolog"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exslices"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

type SynapseDB struct {
	DB *dbutil.Database
}

const PreferredVersion = 88

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
	SELECT events.room_id, events.event_id, events.origin_server_ts
	FROM events
	LEFT JOIN redactions ON events.event_id=redactions.redacts
	WHERE events.sender = $1 AND events.room_id = ANY($2) AND redactions.redacts IS NULL
`

const getEventQuery = `
	SELECT events.room_id, sender, type, state_key, origin_server_ts, json
	FROM events
	LEFT JOIN event_json ON events.event_id=event_json.event_id
	WHERE events.event_id = $1
`

type roomEventTuple struct {
	RoomID    id.RoomID
	EventID   id.EventID
	Timestamp int64
}

var scanRoomEventTuple = dbutil.ConvertRowFn[roomEventTuple](func(row dbutil.Scannable) (t roomEventTuple, err error) {
	err = row.Scan(&t.RoomID, &t.EventID, &t.Timestamp)
	return
})

func (s *SynapseDB) GetEventsToRedact(ctx context.Context, sender id.UserID, inRooms []id.RoomID) (map[id.RoomID][]id.EventID, time.Time, error) {
	output := make(map[id.RoomID][]id.EventID)
	var maxTSRaw int64
	err := scanRoomEventTuple.NewRowIter(
		s.DB.Query(ctx, getUnredactedEventsBySenderInRoomQuery, sender, pq.Array(exslices.CastToString[string](inRooms))),
	).Iter(func(tuple roomEventTuple) (bool, error) {
		output[tuple.RoomID] = append(output[tuple.RoomID], tuple.EventID)
		maxTSRaw = max(maxTSRaw, tuple.Timestamp)
		return true, nil
	})
	return output, time.UnixMilli(maxTSRaw), err
}

func (s *SynapseDB) GetEvent(ctx context.Context, eventID id.EventID) (*event.Event, error) {
	var evt event.Event
	evt.ID = eventID
	// TODO get redaction event?
	err := s.DB.QueryRow(ctx, getEventQuery, eventID).
		Scan(&evt.RoomID, &evt.Sender, &evt.Type.Type, &evt.StateKey, &evt.Timestamp, dbutil.JSON{Data: &evt})
	if err != nil {
		return nil, err
	}
	evt.Type.Class = event.MessageEventType
	if evt.StateKey != nil {
		evt.Type.Class = event.StateEventType
	}
	return &evt, nil
}

func (s *SynapseDB) Close() error {
	return s.DB.Close()
}

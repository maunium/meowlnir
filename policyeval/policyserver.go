package policyeval

import (
	"sync"

	"go.mau.fi/util/exsync"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"

	"go.mau.fi/meowlnir/database"
)

type PolicyServer struct {
	Federation     *federation.Client
	ServerAuth     *federation.ServerAuth
	SigningKey     *federation.SigningKey
	DB             *database.Database
	redactionCache *exsync.Set[id.EventID]
	signatureCache map[id.EventID]*database.PSSignature
	sigCacheMu     sync.RWMutex
}

func NewPolicyServer(fed *federation.Client, serverAuth *federation.ServerAuth, signingKey *federation.SigningKey, db *database.Database) *PolicyServer {
	return &PolicyServer{
		redactionCache: exsync.NewSet[id.EventID](),
		signatureCache: make(map[id.EventID]*database.PSSignature),
		Federation:     fed,
		ServerAuth:     serverAuth,
		DB:             db,
		SigningKey:     signingKey,
		sigCacheMu:     sync.RWMutex{},
	}
}

type PSRecommendation string

const (
	PSRecommendationOk   PSRecommendation = "ok"
	PSRecommendationSpam PSRecommendation = "spam"
)

type LegacyPolicyServerResponse struct {
	Recommendation PSRecommendation `json:"recommendation"`
}

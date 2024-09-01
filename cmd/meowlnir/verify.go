package main

import (
	"context"
	"fmt"

	"github.com/rs/zerolog"
)

func (m *Meowlnir) ensureCrossSigned(ctx context.Context) {
	log := zerolog.Ctx(ctx)
	pubkeys := m.Crypto.Machine().GetOwnCrossSigningPublicKeys(ctx)
	if pubkeys == nil {
		switch m.Config.Appservice.RecoveryKey {
		case "generate":
			err := m.generateRecoveryKey(ctx)
			if err != nil {
				log.Err(err).Msg("Failed to generate recovery key")
			}
		case "":
			log.Warn().Msg("Current device is not verified (no cross-signing keys in account) and no recovery key is set")
		default:
			log.Warn().Msg("Recovery key is set, but cross-signing keys weren't found on the server")
		}
	} else if isVerified, err := m.Crypto.Machine().CryptoStore.IsKeySignedBy(ctx, m.Client.UserID, m.Crypto.Machine().GetAccount().SigningKey(), m.Client.UserID, pubkeys.SelfSigningKey); err != nil {
		log.Err(err).Msg("Failed to check if current device is signed by own self-signing key")
	} else if !isVerified {
		if m.Config.Appservice.RecoveryKey == "" {
			log.Warn().Msg("Current device is not verified and no recovery key is set")
		} else if err = m.verifyWithRecoveryKey(ctx); err != nil {
			log.Err(err).Msg("Failed to verify with recovery key")
		} else {
			log.Info().Msg("Successfully verified current device with recovery key")
		}
	} else {
		log.Debug().Msg("Current device is verified")
	}
}

func (m *Meowlnir) verifyWithRecoveryKey(ctx context.Context) error {
	mach := m.Crypto.Machine()
	keyID, keyData, err := mach.SSSS.GetDefaultKeyData(ctx)
	if err != nil {
		return fmt.Errorf("failed to get default SSSS key data: %w", err)
	}
	key, err := keyData.VerifyRecoveryKey(keyID, m.Config.Appservice.RecoveryKey)
	if err != nil {
		return err
	}
	err = mach.FetchCrossSigningKeysFromSSSS(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to fetch cross-signing keys from SSSS: %w", err)
	}
	err = mach.SignOwnDevice(ctx, mach.OwnIdentity())
	if err != nil {
		return fmt.Errorf("failed to sign own device: %w", err)
	}
	err = mach.SignOwnMasterKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to sign own master key: %w", err)
	}
	return nil
}

func (m *Meowlnir) generateRecoveryKey(ctx context.Context) error {
	mach := m.Crypto.Machine()
	recoverKey, keys, err := mach.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	if err != nil {
		return fmt.Errorf("failed to generate and upload cross-signing keys: %w", err)
	}
	zerolog.Ctx(ctx).Info().Str("recovery_key", recoverKey).Msg("Generated cross-signing keys")
	mach.CrossSigningKeys = keys
	err = mach.SignOwnDevice(ctx, mach.OwnIdentity())
	if err != nil {
		return fmt.Errorf("failed to sign own device: %w", err)
	}
	err = mach.SignOwnMasterKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to sign own master key: %w", err)
	}
	return nil
}

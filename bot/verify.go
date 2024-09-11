package bot

import (
	"context"
	"fmt"
)

func (bot *Bot) GetVerificationStatus(ctx context.Context) (hasKeys, isVerified bool, err error) {
	pubkeys := bot.Mach.GetOwnCrossSigningPublicKeys(ctx)
	if pubkeys != nil {
		hasKeys = true
		isVerified, err = bot.Mach.CryptoStore.IsKeySignedBy(
			ctx, bot.Client.UserID, bot.Mach.GetAccount().SigningKey(), bot.Client.UserID, pubkeys.SelfSigningKey,
		)
		if err != nil {
			err = fmt.Errorf("failed to check if current device is signed by own self-signing key: %w", err)
		}
	}
	return
}

func (bot *Bot) VerifyWithRecoveryKey(ctx context.Context, recoveryKey string) error {
	keyID, keyData, err := bot.Mach.SSSS.GetDefaultKeyData(ctx)
	if err != nil {
		return fmt.Errorf("failed to get default SSSS key data: %w", err)
	}
	key, err := keyData.VerifyRecoveryKey(keyID, recoveryKey)
	if err != nil {
		return err
	}
	err = bot.Mach.FetchCrossSigningKeysFromSSSS(ctx, key)
	if err != nil {
		return fmt.Errorf("failed to fetch cross-signing keys from SSSS: %w", err)
	}
	err = bot.Mach.SignOwnDevice(ctx, bot.Mach.OwnIdentity())
	if err != nil {
		return fmt.Errorf("failed to sign own device: %w", err)
	}
	err = bot.Mach.SignOwnMasterKey(ctx)
	if err != nil {
		return fmt.Errorf("failed to sign own master key: %w", err)
	}
	return nil
}

func (bot *Bot) GenerateRecoveryKey(ctx context.Context) (string, error) {
	recoveryKey, keys, err := bot.Mach.GenerateAndUploadCrossSigningKeys(ctx, nil, "")
	if err != nil {
		return "", fmt.Errorf("failed to generate and upload cross-signing keys: %w", err)
	}
	bot.Mach.CrossSigningKeys = keys
	err = bot.Mach.SignOwnDevice(ctx, bot.Mach.OwnIdentity())
	if err != nil {
		return "", fmt.Errorf("failed to sign own device: %w", err)
	}
	err = bot.Mach.SignOwnMasterKey(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to sign own master key: %w", err)
	}
	return recoveryKey, nil
}

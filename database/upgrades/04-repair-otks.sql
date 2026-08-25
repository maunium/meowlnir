-- v4 (compatible with v1+): Mark OTKs as needing repair
CREATE TABLE otks_need_reset(user_id TEXT PRIMARY KEY);
INSERT INTO otks_need_reset SELECT DISTINCT account_id FROM crypto_account WHERE shared=TRUE;

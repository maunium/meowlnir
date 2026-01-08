-- v2 (compatible with v1+): Allow storing recovery key for bots
ALTER TABLE bot ADD COLUMN recovery_key TEXT;
ALTER TABLE management_room ADD COLUMN encrypted BOOLEAN NOT NULL DEFAULT true;

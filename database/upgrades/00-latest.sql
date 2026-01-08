-- v0 -> v2 (compatible with v1+): Latest schema
CREATE TABLE bot (
    username     TEXT PRIMARY KEY NOT NULL,
    displayname  TEXT NOT NULL,
    avatar_url   TEXT NOT NULL,
    recovery_key TEXT
);

CREATE TABLE management_room (
    room_id      TEXT    PRIMARY KEY NOT NULL,
    bot_username TEXT    NOT NULL,
    encrypted    BOOLEAN NOT NULL DEFAULT true,

    CONSTRAINT management_room_bot_fkey FOREIGN KEY (bot_username) REFERENCES bot (username)
        ON UPDATE CASCADE ON DELETE CASCADE
);

CREATE TABLE taken_action (
    target_user TEXT   NOT NULL,
    in_room_id  TEXT   NOT NULL,
    action_type TEXT   NOT NULL,
    policy_list TEXT   NOT NULL,
    rule_entity TEXT   NOT NULL,
    action      TEXT   NOT NULL,
    taken_at    BIGINT NOT NULL,

    PRIMARY KEY (target_user, in_room_id, action_type)
);

CREATE INDEX taken_action_list_idx ON taken_action (policy_list);
CREATE INDEX taken_action_entity_idx ON taken_action (policy_list, rule_entity);

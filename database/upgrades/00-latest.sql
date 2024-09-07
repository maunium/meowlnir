-- v0 -> v1 (compatible with v1+): Latest schema
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

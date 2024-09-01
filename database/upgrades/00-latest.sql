-- v0 -> v1 (compatible with v1+): Latest schema
CREATE TABLE taken_action (
    policy_list TEXT NOT NULL,
    rule_entity TEXT NOT NULL,
    target_user TEXT NOT NULL,
    action      TEXT NOT NULL
);

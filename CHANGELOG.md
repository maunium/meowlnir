# v0.4.0 (2025-04-16)

* Added support for automatic unbans (thanks to [@nexy7574] in [#2]).
* Merged separate user and server ban commands into one with validation to
  prevent banning invalid entities.
* Added `!send-as-bot` command to send a message to a room as the
  moderation bot.
* Added support for redacting individual events with `!redact` command.
* Added `!redact-recent` command to redact all recent messages in a room.
* Added `!powerlevel` command to change a power level in rooms.
* Added `!help` command to view available commands.
* Added `!search` command to search for policies using glob patterns.
* Added support for redacting messages on all server implementations
  (thanks to [@nexy7574] in [#16]).
* Fixed server ban evaluation to ignore port numbers as per
  [the spec](https://spec.matrix.org/v1.13/client-server-api/#mroomserver_acl).

[#2]: https://github.com/maunium/meowlnir/pull/2
[#16]: https://github.com/maunium/meowlnir/pull/16

# v0.3.0 (2025-03-16)

* Added support for managing server ACLs.
* Added support for [MSC4194] as an alternative to database access for redacting
  messages from a user efficiently.
* Made encryption and database access optional to allow running with
  non-Synapse homeservers.
* Added `!kick` command to kick users from all protected rooms.
* Added support for blocking incoming invites on Synapse.
  * Requires installing the [synapse-http-antispam] module to forward callbacks
    to Meowlnir.
  * Pending invites can also be automatically rejected using a double puppeting
    appservice if the ban comes in after the invite.
* Added support for [MSC4204]: `m.takedown` moderation policy recommendation.
* Added support for [MSC4205]: Hashed moderation policy entities.
* Fixed events not being redacted if the user left before being banned.
* Updated `!match` command to list protected rooms where the user is joined.
* Changed report endpoint to fetch event using the user's token instead of the
  bot's (thanks to [@nexy7574] in [#3]).
* Changed ban execution to ignore policies with the reason set to the string
  `<no reason supplied>`. The ban will be sent without a reason instead.
* Changed management room to ignore unverified devices to implement [MSC4153].
* Changed API path prefix from `/_matrix/meowlnir` to `/_meowlnir`.

[synapse-http-antispam]: https://github.com/maunium/synapse-http-antispam
[MSC4153]: https://github.com/matrix-org/matrix-spec-proposals/pull/4153
[MSC4194]: https://github.com/matrix-org/matrix-spec-proposals/pull/4194
[MSC4204]: https://github.com/matrix-org/matrix-spec-proposals/pull/4204
[MSC4205]: https://github.com/matrix-org/matrix-spec-proposals/pull/4205
[@nexy7574]: https://github.com/nexy7574
[#3]: https://github.com/maunium/meowlnir/pull/3

# v0.2.0 (2024-10-16)

* Added support for banning users via the report feature.
  * This requires setting `report_room` in the config and proxying the Matrix
    C-S report endpoint to Meowlnir.
* Added support for notifying management room when the bot is pinged in a
  protected room.
* Added `!ban` command to management rooms.
* Added `hacky_rule_filter` to filter out policies which are too wide.
* Fixed watched lists being evaluated in the wrong order.
* Fixed newly added policy evaluation not considering existing unban policies.
* Fixed handling redactions of policy events.

# v0.1.0 (2024-09-16)

Initial release.

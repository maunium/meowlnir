# v25.12

* Added endpoints for deleting bots and management rooms.
* Added endpoint for fetching own management rooms using a Matrix access token.
  * The Matrix-authed endpoints are disabled by default and can be enabled in
    the config. They will be used for a management web interface in the future.
* Changed `!match` and `!search` command to always only look in watched lists,
  regardless of `untrusted` flag.
* Fixed new bans trying to ban users in rooms that were unprotected earlier.

# v25.11

* Added flag for force purging a room.
* Added support for new `/sign` endpoint for [MSC4284] policy servers
  (thanks to [@nexy7574] in [#44]).
* Fixed bots trying to remove bans made by other bots on the same Meowlnir
  instance when a policy is removed.
* Fixed kick command not reading room parameter correctly
  (thanks to [@nexy7574] in [#45]).
* Removed unnecessary 10 second sleep when first creating a bot.

[#44]: https://github.com/maunium/meowlnir/pull/44
[#45]: https://github.com/maunium/meowlnir/pull/45

# v25.10

* Switched to calendar versioning.
* Added `untrusted` flag to enforce membership checks before accessing policy
  list cache.
* Added automatic bot provisioning command with configuration defined in the
  `meowlnir4all` section.
* Added command to change bot profile from management room.

# v0.8.0 (2025-09-16)

* Added PDU validation to policy server.
* Added note for policy list change notices that were delayed.
* Added command flag to kick user in a specific room only
  (thanks to [@nexy7574] in [#39]).
* Added option to not require encryption in management room even if encryption
  is set up in config.
* Fixed policy server redacting events multiple times.
* Fixed spoilers in bot notices not being applied properly in some cases.
* Fixed policy list cache not handling removals of duplicate policies correctly.

[#39]: https://github.com/maunium/meowlnir/pull/39

# v0.7.0 (2025-08-16)

* Bumped minimum Go version to 1.24.
* Added support for creator power in room v12.
* Added appservice ping at startup to ensure homeserver -> meowlnir connection
  works similar to what bridges do.
* Added support for `federated_user_may_invite` callback and [MSC4311].
* Added custom API for querying policy lists that Meowlnir has cached.
* Fixed various bugs in experimental built-in policy server.
  * Note that the policy server is not considered stable yet, so it should
    not be used in production.

[MSC4311]: https://github.com/matrix-org/matrix-spec-proposals/pull/4311

# v0.6.0 (2025-06-16)

* Added experimental built-in policy server as per [MSC4284]
  (thanks to [@nexy7574] in [#21]).
* Added support for deleting rooms (manually with a command, when receiving
  a ban policy, or when discovering a room with a ban policy).
* Added support for referencing users by matrix.to URL or matrix: URI in
  most commands.
* Added support for sending `redact_events` flag on ban events as per [MSC4293].
* Changed command output to hide potentially sensitive names
  (thanks to [@JadedBlueEyes] in [#23]).
* Changed invite block notices to not include intentional mentions.
* Changed `!match` command to allow querying multiple entities at once.
* Updated Docker image to Alpine 3.22.
* Fixed ban removals sending empty entity/reason/recommendation fields instead
  of omitting them entirely.
* Fixed room reporting endpoint (thanks to [@spaetz] in [#24]).

[MSC4284]: https://github.com/matrix-org/matrix-spec-proposals/pull/4284
[MSC4293]: https://github.com/matrix-org/matrix-spec-proposals/pull/4293
[#21]: https://github.com/maunium/meowlnir/pull/21
[#23]: https://github.com/maunium/meowlnir/pull/23
[#24]: https://github.com/maunium/meowlnir/pull/24
[@spaetz]: https://github.com/spaetz
[@JadedBlueEyes]: https://github.com/JadedBlueEyes

# v0.5.0 (2025-05-16)

* Added option to suppress notifications of policy list changes.
* Added config option for customizing which ban reasons trigger automatic
  redactions (thanks to [@nexy7574] in [#18]).
* Added `!deactivate` command to deactivate local accounts using the Synapse
  admin API.
* Added support for automatically suspending local accounts using the Synapse
  admin API when receiving a ban policy.
  * Must be enabled per-policy-list using the `auto_suspend` flag.
* Added debouncing for server ACL updates to prevent spamming events when
  multiple changes are made quickly.
* Added deduplication to management room commands to prevent accidentally
  sending bans that already exist.
* Fixed removing hashed policies using commands.
* Fixed fallback redaction mechanism not redacting state events
  (thanks to [@nexy7574] in [#19]).
* Fixed the API returning an invalid response when creating a management room.
* Switched to mautrix-go's new bot command framework for handling commands.
* Removed policy reason from error messages returned by antispam API.

[#18]: https://github.com/maunium/meowlnir/pull/18
[#19]: https://github.com/maunium/meowlnir/pull/19

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

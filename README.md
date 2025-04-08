# Meowlnir
An opinionated Matrix moderation bot. Currently only compatible with Synapse.

## Discussion
Matrix room: [#meowlnir:maunium.net](https://matrix.to/#/#meowlnir:maunium.net)

## Setup
Docker images can be found at [`dock.mau.dev/maunium/meowlnir`] and binaries
are built in [mau.dev CI] the same way as all mautrix bridges. `build.sh` also
works the same way as in bridges.

[`dock.mau.dev/maunium/meowlnir`]: https://mau.dev/maunium/meowlnir/container_registry
[mau.dev CI]: https://mau.dev/maunium/meowlnir/-/pipelines?ref=main

### Configuration
The example config can be found in [./config/example-config.yaml]. Meowlnir
requires both its own database (both SQLite and Postgres are supported), as
well as read-only access to the Synapse database.

[./config/example-config.yaml]: (https://github.com/maunium/meowlnir/blob/main/config/example-config.yaml).

#### Notes on Synapse database access
A read-only user can be created with something like this:

```sql
CREATE USER meowlnir WITH PASSWORD '...';
GRANT CONNECT ON DATABASE synapse TO meowlnir;
GRANT USAGE ON SCHEMA public TO meowlnir;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO meowlnir;
```

The current primary reason Meowlnir reads the database directly is to get
events to redact more efficiently, and to find soft-failed events (which
may not have soft-failed on other servers).

To make finding events more efficient, you may want to add an index:

```sql
CREATE INDEX meowlnir_event_sender_idx ON events (room_id, sender);
```

### Appservice registration
After configuring Meowlnir itself, make a registration file, such as this:

```yaml
# ID and tokens must be exactly the same as in the Meowlnir config.
id: ...
as_token: ...
hs_token: ...
# The URL where the homeserver can reach Meowlnir.
url: http://localhost:29339
# This doesn't matter, just needs to be unique.
sender_localpart: any random string here
# Meowlnir will not handle ratelimits, so this must be false.
rate_limited: false
# Meowlnir uses MSC3202, MSC4190 and MSC4203 for encryption, so they must be enabled.
org.matrix.msc3202: true
io.element.msc4190: true
# push_ephemeral is the old name of receive_ephemeral, as Synapse hasn't stabilized MSC2409 support yet.
# Enabling 2409/receive_ephemeral is required for MSC4203.
de.sorunome.msc2409.push_ephemeral: true
receive_ephemeral: true
# Add the bots you want here. If you only want one bot, a static regex is enough.
# Multiple bots are supported too and can be dynamically added if you set a non-static regex (e.g. `@moderation_.+:example\.com`)
namespaces:
  users:
  - regex: '@abuse:example\.com'
    exclusive: true
```

Additionally, you'll need to enable some experimental features in the Synapse config:

```yaml
experimental_features:
  # Actually MSC4203, but it was previously a part of MSC2409
  msc2409_to_device_messages_enabled: true
  # MSC3202 has two parts, both need to be enabled
  msc3202_device_masquerading: true
  msc3202_transaction_extensions: true
```

### Creating bots
You may have noticed that the config file doesn't have anything about the bot
username or management rooms. This is because the bots and management rooms can
be created dynamically at runtime and are saved in the database. The management
secret specified in the config is used to authenticate with the API that can
create bots.

Currently existing endpoints:

* `GET /_meowlnir/v1/bots` - List all bots
* `PUT /_meowlnir/v1/bot/{localpart}` - Create a bot
* `POST /_meowlnir/v1/bot/{localpart}/verify` - Cross-sign a bot's device
* `PUT /_meowlnir/v1/management_room/{roomID}` - Define a room as a management room

There will be a CLI and/or web UI later, but for now, you can use curl:

```shell
export AUTH="Authorization: Bearer $MANAGEMENT_SECRET"
```

First, create a bot. This example copies matrix.org's admin bot (`abuse` as the
username, `Administrator` as the displayname, and the same avatar):

```shell
curl -H "$AUTH" https://meowlnir.example.com/_meowlnir/v1/bot/abuse -XPUT -d '{"displayname": "Administrator", "avatar_url": "mxc://matrix.org/NZGChxcCXbBvgkCNZTLXlpux"}'
```

Assuming you didn't have an @abuse user before or if it didn't have encryption,
you can have Meowlnir generate cross-signing keys to verify itself. This
command will return the recovery key. Make sure to save it!

```shell
curl -H "$AUTH" https://meowlnir.example.com/_meowlnir/v1/bot/abuse/verify -d '{"generate": true}'
```

Alternatively, if the user already has cross-signing set up, you can provide
the recovery key for verification:

```shell
curl -H "$AUTH" https://meowlnir.example.com/_meowlnir/v1/bot/abuse/verify -d '{"recovery_key": "EsT* ****..."}'
```

Finally, you need to define a management room. Create the room normally, get
the room ID and run:

```shell
curl -H "$AUTH" -X PUT 'https://meowlnir.example.com/_meowlnir/v1/management_room/!randomroomid:example.com' -d '{"bot_username": "abuse"}'
```

After defining the room, you can invite the bot, and it should accept the invite
(you can also invite the bot beforehand if you prefer).

### Configuring the bot
The bot will read state events in the management room to determine which policy
lists to subscribe to and which rooms to protect. Adding these will happen with
commands in the future, but for now, you can send state events manually.

#### Subscribing to policy lists
The `fi.mau.meowlnir.watched_lists` state event is used to subscribe to policy
lists. It must have a `lists` key, which is a list of objects. Each object must
contain `room_id`, `shortcode` and `name`, and may also specify `dont_apply`
and `auto_unban`.

For example, the event below will apply CME bans to protected rooms, as well as
watch matrix.org's lists without applying them to rooms (i.e. the bot will send
messages when the list adds policies, but won't take action based on those).

```json
{
	"lists": [
		{
			"auto_unban": true,
			"name": "CME bans",
			"room_id": "!fTjMjIzNKEsFlUIiru:neko.dev",
			"shortcode": "cme"
		},
		{
			"auto_unban": true,
			"dont_apply": true,
			"name": "matrix.org coc",
			"room_id": "!WuBtumawCeOGEieRrp:matrix.org",
			"shortcode": "morg-coc"
		},
		{
			"auto_unban": true,
			"dont_apply": true,
			"name": "matrix.org tos",
			"room_id": "!tUPwPPmVTaiKXMiijj:matrix.org",
			"shortcode": "morg-tos"
		}
	]
}
```

To make the bot join a policy list, use the `!join <room ID or alias>` command.

#### Protecting rooms
Protected rooms are listed in the `fi.mau.meowlnir.protected_rooms` state event.
The event content is simply a `rooms` key which is a list of room IDs.

```json
{
	"rooms": [
		"!randomid:example.com",
		"!anotherrandomid:example.com"
	]
}
```

After adding rooms to this list, you can invite the bot to the room, or use the
`!join` command.

#### Blocking invites
To use policy lists for blocking incoming invites, install the
[synapse-http-antispam] module, then configure it with the ID of the management
room you want to use plus the antispam API token from the Meowlnir config file:

[synapse-http-antispam]: https://github.com/maunium/synapse-http-antispam

```yaml
modules:
  - module: synapse_http_antispam.HTTPAntispam
    config:
      base_url: http://localhost:29339/_meowlnir/antispam/<management room ID>
      authorization: <value of antispam.secret>
      enabled_callbacks:
      - user_may_invite
      - user_may_join_room
      async:
        user_may_join_room: true
```

The `user_may_invite` callback is used to block invites from users who are
banned on any of the policy lists that the management room is subscribed to.

The `user_may_join_room` callback is used to track whether non-blocked invites
have been accepted. If `auto_reject_invites_token` is set in the config,
Meowlnir will automatically reject pending invites to rooms from banned users.
Even if this callback is not enabled, Meowlnir will still check whether the
invites are pending to avoid rejecting already-accepted invites.

### Running on a non-Synapse server
While Meowlnir is designed to be used with Synapse, it can be used with other
server implementations as well.

If your server doesn't support all the MSCs mentioned in the appservice
registration section, set `encryption` -> `enable` to `false` to disable
encryption entirely.

The Synapse database connection can be skipped by leaving `type` and `uri`
blank in the config. However, redacting messages from banned users will only
work if you either provide a Synapse database or implement [MSC4194] on the
server.

You can technically point it at another server's database too; it doesn't have
to be the database of the server the bot is connected to. If doing that, ensure
that the Synapse is in all the protected rooms so that it receives all events
that may need to be redacted in the future.

[MSC4194]: https://github.com/matrix-org/matrix-spec-proposals/pull/4194

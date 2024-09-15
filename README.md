# Meowlnir
An opinionated Matrix moderation bot. Currently only compatible with Synapse.

## Discussion
Matrix room: [#meowlnir:maunium.net](https://matrix.to/#/#meowlnir:maunium.net)

## Setup
Docker images can be found at [`dock.mau.dev/maunium/meowlnir`] and binaries
are built in [mau.dev CI] the same way as all mautrix bridges. `build.sh` also
works the same way as in bridges.

[`dock.mau.dev/maunium/meowlnir`]: https://mau.dev/maunium/meowlnir/container_registry
[mau.dev CI]: https://mau.dev/maunium/meowlnir/-/pipelines

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
# Meowlnir uses MSC2409 & MSC3202 for encryption, so they must be enabled.
org.matrix.msc3202: true
de.sorunome.msc2409.push_ephemeral: true
push_ephemeral: true
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
  msc2409_to_device_messages_enabled: true
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

* `GET /_matrix/meowlnir/v1/bots` - List all bots
* `PUT /_matrix/meowlnir/v1/bot/{localpart}` - Create a bot
* `POST /_matrix/meowlnir/v1/bot/{localpart}/verify` - Cross-sign a bot's device
* `PUT /_matrix/meowlnir/v1/management_room/{roomID}` - Define a room as a management room

There will be a CLI and/or web UI later, but for now, you can use curl:

```shell
export AUTH="Authorization: Bearer $MANAGEMENT_SECRET"
```

First, create a bot. This example copies matrix.org's admin bot (`abuse` as the
username, `Administrator` as the displayname, and the same avatar):

```shell
curl -H "$AUTH" https://meowlnir.example.com/_matrix/meowlnir/v1/bot/abuse -XPUT -d '{"displayname": "Administrator", "avatar_url": "mxc://matrix.org/NZGChxcCXbBvgkCNZTLXlpux"}'
```

Assuming you didn't have an @abuse user before or if it didn't have encryption,
you can have Meowlnir generate cross-signing keys to verify itself. This
command will return the recovery key. Make sure to save it!

```shell
curl -H "$AUTH" https://meowlnir.example.com/_matrix/meowlnir/v1/bot/abuse/verify -d '{"generate": true}'
```

Alternatively, if the user already has cross-signing set up, you can provide
the recovery key for verification:

```shell
curl -H "$AUTH" https://meowlnir.example.com/_matrix/meowlnir/v1/bot/abuse/verify -d '{"recovery_key": "EsT* ****..."}'
```

Finally, you need to define a management room. Create the room normally, get
the room ID and run:

```shell
curl -H "$AUTH" 'https://meowlnir.example.com/_matrix/meowlnir/v1/management_room/!randomroomid:example.com' -d '{"bot_username": "abuse"}'
```

After defining the room, you can invite the bot, and it should accept the invite
(if you invite beforehand, it won't accept).

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

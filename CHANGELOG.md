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

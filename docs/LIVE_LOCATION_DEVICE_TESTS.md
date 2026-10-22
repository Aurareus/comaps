# Live location: on-device checklist

Phase 2 was built and tested without a phone or an emulator (desktop tests, a C++ peer and a Python
peer over a real relay). This checklist covers what only phones can show: the Definition of Done
of the brief, and the Android code paths no test has run yet. Each check says what to do, what
should happen, and what to write down.

## Setup

- **Build** (on a machine with the Android SDK and NDK):

  ```bash
  cd android
  ./gradlew assembleFdroidDebug -Parm64 -PdisableHWAsan
  adb install -r app/build/outputs/apk/fdroid/debug/CoMaps-*-fdroid-debug.apk
  ```

  The package is `app.comaps.fdroid.debug`. Use the fdroid build on at least one phone without
  Google Play services (check 9).
- **Phones:** A (sharer) and B (viewer), Android 7 or later, on different networks: for example A on
  mobile data and B on Wi-Fi.
- **Turn it on, on both:** Settings → Live location sharing → the switch "Live location sharing".
  The "What relays can see" screen appears once. "Share My Location" in the main menu
  then opens the feature's screen (below: "Share My Location").
- **Logs:** `adb logcat | grep -iE "live ?location|LiveLocation|OkHttpTransport|KeystoreKeyWrapper"`.
  The core logs relay failures as "Relay connection failed: <url> <reason>".
- **Test peer** (check 5), on a computer, from `tools/python/live_location` (see its README for
  the virtualenv): `.venv/bin/python -I peer.py --state peer.json --name Peer ...`.
- **Traffic:** PCAPdroid (F-Droid) with an app filter on CoMaps shows each connection and its
  bytes, without root.

## Definition of Done

### 1. Pairing in under a minute (QR, in person)

1. A: menu → Share My Location → Add contact. A QR code appears, with "Expires in 10 min".
2. B: scan the code with the stock camera app (or any QR app that opens links). CoMaps asks
   "Connect with whoever created this invite? They will see your name, Bob." → "Connect"; then
   "Connecting…".
3. Both show the same six-digit code. B: "Codes match". A: "Bob wants to connect. Check that Bob's
   screen shows …" → "Codes match, connect".
4. Both: "Connected with …". In the contacts list each shows the other as "Verified".

Record: the time from A tapping "Add contact" to both showing "Connected" (target: under a minute),
and whether the stock camera opened CoMaps.

### 2. Pairing by link

1. A: Add contact → "Share a link instead" → send the link to B through a messenger.
2. B: tap the link: CoMaps asks before connecting, as in check 1. If the messenger does not make
   `comaps://` links tappable, copy it, then in CoMaps: Share My Location → Add contact → "Paste
   invite" (no question then: pasting is the choice).
3. A: "Bob wants to connect. Compare this code with Bob, by phone or in person" → try "Connect
   without comparing" once: the contact shows "Not verified" on A's side, and Manage sharing warns
   about it.
4. Optional: close CoMaps on B before A decides, reopen it later: connecting finishes then.

Record: whether the link was tappable in the messenger used.

### 3. A's marker follows within about 5 s

1. A: Share My Location → Share live location → "For: 1 hour" → tick B. Allow precise location,
   and notifications on Android 13+. B moves up to "Currently sharing with", "Starting…", and the
   share starts about 2.5 s later, or at once on leaving the screen. A's notification reads "Sharing
   your live location · With Bob · until …". A round indicator with a "1" in its pin appears at the
   top right of the map, blinking between grey and blue, below track recording's if a track is being
   recorded, and the compass sits below it.
2. B: open the map. A's dot appears within a few seconds: a coloured circle, A's name under it.
   B's own position arrow is drawn above it: with the phones side by side, A's dot can hide under
   it. Move apart, or look for A's name.
3. B: tap A's dot, then A's name. Each opens a sheet over the map: A's name and status ("Sharing
   their location with you until …"), the last update, the accuracy, "Center" and "Contact
   details". The lines update in place while A moves, without the sheet flickering. "Center" centres
   the map on A; "Contact details" opens A's screen. A long tap on the dot opens the usual place
   page, titled "Alice".
4. A: walk or drive. B's dot follows, each move within about 5 s. A logs "location: Live" (B's
   watch signals arrived).
5. B: close CoMaps. After about 2 minutes A goes back to the idle rate: a move beyond both fixes'
   accuracies (at least 20 m), or every 5 minutes. A phone lying still should then publish about
   every 5 minutes, not every 30 s.

Record: a few delays between A's move and B's dot moving; whether the dot greys out when updates
stop (after 2 minutes).

### 4. Stop

1. A: tap "Stop" in the notification, or tap the map's indicator → Stop all (two taps), or Share My
   Location → "Stop sharing location".
2. A's notification and the indicator go away. B's dot greys, then disappears; B's contact no
   longer says "Sharing their location with you".

Record: how long B took to show the end.

### 5. Revocation, with the test peer

1. Pair A with the test peer: A → Add contact → Share a link instead → copy the link, then
   `peer.py --state peer.json --name Peer join 'comaps://live/pair#…'`, and compare codes.
2. A shares with B and Peer. Run `peer.py --state peer.json follow --minutes 20`: it prints each
   position.
3. A: Manage sharing → untick Peer (or Peer's Contact details → "Stop sharing with Peer"). B keeps
   following A.
4. The peer reports "removed", then keeps trying its old key on everything A publishes. When it
   ends it prints `summary A: N events after the removal, 0 decrypted with the old key`.

Expected: B follows A's new stream after at most about 2 minutes (the new stream stays silent for
30 to 120 s); the peer decrypts 0 events after the removal.

### 6. Time-limited shares end on time

1. A shares with B for 15 min (Manage sharing → For: 15 min → tick B).
2. At the end time the share stops by itself: notification gone, B sees the end.
3. Again with "For: Until…", a time a few minutes ahead on the clock; and once more, changing the
   end from B's Contact details on A ("Change") to a minute from now: the share ends then, and B's
   dot carries on until it does (no re-key, so no pause).

Record: the difference between the end time shown and the actual end (expect under a minute).

### 7. Two of three relays down

The core moves past failing relays (tests: `Manager_WorksWithTwoOfThreeRelaysDown`, relay pool
tests). On phones, give both the same three relays, the dead ones first so that the listening relay
has to move too: Settings → Live location sharing → Relays: `wss://dead1.invalid`,
`wss://dead2.invalid`, `wss://nos.lol` (add the two, move them up, remove the other defaults).
Identical lists keep relay consent out of the way. Alternatively, block two default relays for
CoMaps with NetGuard or RethinkDNS.

Expected: pairing, sharing, live updates and viewing still work through the third relay, after a
delay of at most about 25 s while the dead ones fail. Afterwards, restore the default relays.

### 8. No traffic when unused

With PCAPdroid filtering on CoMaps:

1. Feature off: no connection to any relay, ever.
2. Feature on, no shares, CoMaps in the background: no connection.
3. Feature on, CoMaps in the foreground with at least one contact: connections to the relays
   (asking whether anyone shares); they close about a minute after CoMaps goes to the background.
4. Sharing, nobody watching, in the background: one connection held open (the listening relay),
   plus short publishes.

Record: anything that connects when it should not.

### 9. Without Play services

On the phone without Google Play services (fdroid build): checks 1, 3 and 4 work the same. Location
comes from Android's own providers.

### 10. Battery and data for one hour

Measure on A, screen off, sharing with B for one hour, twice: once with nobody watching (idle) and
once with B's map open the whole hour (live). Repeat on Wi-Fi and on mobile data if possible.

- Battery: note the percentage at the start and end of the hour, unplugged. For a baseline,
  measure an hour with the same phone idle and live location not sharing. For detail:

  ```bash
  adb shell dumpsys batterystats --reset
  # unplug, share for an hour with the screen off, plug in
  adb shell dumpsys batterystats --charged app.comaps.fdroid.debug > batterystats.txt
  ```

  `batterystats.txt` has CoMaps' mobile radio active time, GPS time and wakeups.
- Data: PCAPdroid's per-app total over the hour, or Settings → Network → App data usage.

The design's estimates to compare with (LIVE_LOCATION.md §10.3, LTE, three relays): unwatched and
stationary about 0.5–1 %/h and 0.2 MB/h; unwatched and walking 1–3 %/h and 0.2–0.6 MB/h; watched
the whole hour 4–8 %/h and 2.5 MB/h. On Wi-Fi the idle cases drop below 1 %/h. Note whether A moved.

Record: %/h and MB/h for each run; radio active time and GPS time if measured.

### 11. What relays can see, on one screen

Settings → Live location sharing → "What relays can see", with the feature on and off. It fits one
screen on a phone, or nearly; it says what relays can and cannot see (§11.6).

## New code paths to check

- **Installing over the previous build.** This build reads no store of an earlier one (LIVE_LOCATION.md
  §26). Installed over the previous build, Share My Location says the data cannot be read and offers
  "Delete all live location data": delete it on every phone, then connect the phones again.
- **The dot's sheet.** Tap a contact's dot: the sheet rises without dimming the map, and the zoom and
  my-position buttons rise above it. With the sheet open, move and zoom the map; "Center" puts the
  contact in the part of the map above the sheet. Drag the sheet down: it closes, and the buttons
  come back down. Open it again, then each of these closes it: back; the main menu; search; planning
  a route; a long tap with "full screen on long tap" on (Settings → Interface). A place tapped on
  the map opens its place page in the sheet's stead, and another contact's dot shows that contact.
  "Contact details", then back: the sheet is still there. Rotate the phone: it is still there.
  Sideways, the sheet is no wider than a place page, and centred like one.
- **The left button.** Settings → Interface → Left button setup lists "Share Live Location". Pick it:
  the map's left button shows the feature's icon, and a tap opens Manage sharing. With no contacts,
  it opens Share My Location; with the feature off, the explanation. The main menu still has "Share
  My Location".
- **Saving fails.** On A, with CoMaps open: `adb shell run-as app.comaps.fdroid.debug chmod 500
  no_backup`, then rename a contact: CoMaps says once that it couldn't save the live location data,
  with only OK, and Settings stays usable. Rename again: nothing more is said. `adb shell run-as
  app.comaps.fdroid.debug chmod 700 no_backup` afterwards, then rename once more so that the store
  is written.
- **Route planning.** With a track being recorded and a share running, plan a route: both indicators
  sit below the header, clear of it, upright and sideways.
- **Icons.** The indicator's icon and the Settings icons of the feature are not cut off at the sides.
  "Allow viewers to request live updates" has two arrows turning in a circle.
- **Names and relays.** "Appear as" or renaming a contact with a tab or a line break pasted in: "A
  name can't contain tabs or line breaks." Adding the relay `wss://a"b.example`: refused.
- **The map indicator.** While sharing: at the top right where track recording's would be, with the
  number of people in its pin (1, then 2 or more); blinking between grey and blue. Start recording a
  track: the indicator moves below track recording's, both blink in step, and the compass sits
  below both, in the regular map, in route planning and in navigation, upright and sideways. Tapping
  the map to hide the buttons hides it too.
- **Contacts' dots** are a little larger than before (20 dp across).
- **The dot colour.** A: Settings → Live location sharing → Color you appear as → Teal, while sharing with
  B: B's dot for A turns teal within seconds, and stays teal after B restarts CoMaps. "Automatic":
  B's app picks A's colour again.
- **Manage sharing.** The second heading reads "Start sharing". Tick two contacts within a second or two: one change, so B, already
  following, sees a single pause (30 to 120 s). Untick one: it stops at once. Tick one and leave the
  screen at once: the share includes it. "Until…" with a time that has already passed today means
  tomorrow; rotating the phone while its clock shows closes the clock, as it does the "For" list.
  "Stop all" stops everything; so does Share My Location → "Stop sharing location".
- **Contact details.** Title "Contact details". While sharing with the contact: "Sharing your
  location with them", "Until …", "Change" (earlier, later, until stopped), above the last update,
  and "Stop sharing with …". "Hide on the map" has its explanation below the switch, above "Show on
  the map". "Battery low" when the contact's battery is low (below). While the contact's position
  updates, the screen does not jump, a tap on a button is not lost, and TalkBack keeps its place.
  "Stop sharing with …" just after the share with that contact ended: no error, the others go on.
  Deleting the contact returns to Share My Location, with that title.
- **Add contact.** Leave the screen while the QR code shows: "Leave the invite waiting?". "Leave it
  waiting": Share My Location lists "Invite waiting", and B can still use the code. "Cancel invite"
  (here or on the screen): back on Share My Location, titled "Share My Location".
- **Relay consent, three answers.** On A: Settings → Live location sharing → Relays → Add relay → a
  relay of your own, then "Move up" to make it first. Share with B: B is asked about that relay,
  once, and the question says live updates need it. "Not now": B's contact shows "Live updates off"
  and its details "Live updates from A need …"; close CoMaps on B (swipe it from the recent apps) and
  open it again: B is asked again, once. "Don't allow": never asked again, and Settings → Relays for
  contacts lists the relay under "Refused", with A's name; "Allow" there turns live updates on. A tap
  on the label in A's details asks the question again.
- **An unreachable contact.** On A: Relays → remove every relay but your own. On B, answer "Don't
  allow" about it: B's contact list shows A as "Unreachable until you allow a relay", A's details say
  "Messages to A need …", and in Manage sharing A carries that warning; ticking A asks about the
  relay first, and "Allow" then shares with A. Then an invite through that relay: on B, Settings →
  Live location sharing → Relays for contacts → revoke it; A makes a link invite, which has only that
  relay; B opens the link, answering "Not now" if asked: B's screen names the relay with "Allow …",
  rather than calling the invite invalid, and "Allow …" connects. Restore A's relays afterwards.
- **Settings.** The rows have icons, and values or explanations below their titles: Appear as (your
  name), Color you appear as, Relays (a dialog: the list, moving up, removing, adding), Relays for contacts
  (a dialog: allowed ones to revoke, refused ones to allow), the two live update switches, Stop
  sharing at low battery, Delete. "Request live updates when viewing" off → A stays idle while B
  watches. Turn the feature off: the rows stay, greyed, titles only; "What relays can see" and
  "Delete all live location data" still work. On a phone with Android 5 or 6, if you have one, the
  entry is not listed at all.
- **Low battery.** While sharing, `adb shell dumpsys battery unplug; adb shell dumpsys battery set
  level 14`: B's sheet and A's details on B show "Battery low"; `adb shell dumpsys battery set ac 1`
  (charging): it goes. Then the stop, unplugged again (`set ac 0`): set "Stop sharing at low
  battery" to 15 %, `set level 20`, `set level 15` → the share stops. Start a share at level 12: it
  runs (you chose to share). `set ac 1`, `set level 15`, `set ac 0`: it still runs (charging up to
  the level is not above it), and so after picking 15 % again in Settings. `set ac 1`, `set level
  20`, `set level 12`: it runs while plugged in; `set ac 0` → it stops. "Never": nothing stops it.
  `adb shell dumpsys battery reset` afterwards.
- **Changing home relays** (spec §11). With B's CoMaps closed, A: Settings → Live location sharing →
  Relays → add a relay (for instance `wss://relay.damus.io`) and remove one default. A's contact list
  shows B as "Hasn't picked up your new relays yet"; B's details explain. B opens CoMaps: B is asked
  once about the new relay only if no relay A kept is one B may use. With A's CoMaps open too, the
  label on A's side goes within seconds. Then B shares with A: A sees B's share. While A shares
  with B, a change moves the share: B's dot carries on after 30–120 s.
- **The daily ratchet** (D16). `adb shell dumpsys jobscheduler | grep -i -A3 comaps.fdroid.debug`
  lists WorkManager's job while the feature is on, and nothing once it is off.
- **No silent sharing.** While sharing: turn off CoMaps' notifications in Android settings → the
  share stops at once on Android 9+ (the system announces the block), otherwise at the next fix
  (2–30 s); the next live location screen or the map says why.
  Swipe the notification away (Android 13+) → it comes back at once. On Android 13+, deny the
  notification permission → sharing does not start, and Manage sharing explains.
- **Resume after the process died.** While sharing: `adb shell am kill app.comaps.fdroid.debug`
  does not stop a foreground service, so use `adb shell am force-stop app.comaps.fdroid.debug`,
  then open CoMaps: the map offers "Resume sharing?" with the same people and end time. With
  CoMaps' notifications turned off, "Resume" leads to Manage sharing, which asks for them; back
  from the settings with them on, Manage sharing offers "Resume" at its top. A share "For 15
  minutes", force-stopped, with CoMaps opened again after its end: nothing is offered.
- **Share My Location.** With the feature on, the menu's "Share My Location" opens the feature's
  screen; its "Send current location" opens the system share sheet with a link to the current
  position, as the menu entry does with the feature off. While sharing, the row "Sharing with N
  people" is below "Add contact".
- **The echo check.** Over an hour of sharing, logcat should not show "Relay accepts events without
  delivering them" for a relay that works: each one would be a false alarm, costing a move to the
  next relay.
- **Deleting.** Settings → Live location sharing → "Delete all live location data" → contacts gone.
  Also with the feature off.
- **Turning it off while sharing.** Settings → Live location sharing → turn the switch off → the
  share stops (B sees the end), the notification goes.

## What to send back

For each check: passed or not, the numbers recorded, and for failures the logcat around them and a
screenshot. Layout problems (overlaps, cut-off text, the QR code's size) with a screenshot.

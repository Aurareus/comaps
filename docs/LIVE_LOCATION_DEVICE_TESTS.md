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
- **Turn it on, on both:** Settings → Advanced → "Live location sharing (experimental)". The
  "How live location stays private" screen appears once. "Live location" is then in the main menu.
- **Logs:** `adb logcat | grep -iE "live ?location|LiveLocation|OkHttpTransport|KeystoreKeyWrapper"`.
  The core logs relay failures as "Relay connection failed: <url> <reason>".
- **Test peer** (check 5), on a computer, from `tools/python/live_location` (see its README for
  the virtualenv): `.venv/bin/python -I peer.py --state peer.json --name Peer ...`.
- **Traffic:** PCAPdroid (F-Droid) with an app filter on CoMaps shows each connection and its
  bytes, without root.

## Definition of Done

### 1. Pairing in under a minute (QR, in person)

1. A: menu → Live location → Add contact. A QR code appears, with "Expires in 10 min".
2. B: scan the code with the stock camera app (or any QR app that opens links). CoMaps asks
   "Connect with whoever sent this invite? They will see your name, Bob." → "Connect"; then
   "Connecting…".
3. Both show the same six-digit code. B: "Codes match". A: "Bob wants to connect. Check that Bob's
   screen shows …" → "Codes match, connect".
4. Both: "Connected with …". In the contacts list each shows the other as "Verified".

Record: the time from A tapping "Add contact" to both showing "Connected" (target: under a minute),
and whether the stock camera opened CoMaps.

### 2. Pairing by link

1. A: Add contact → "Share a link instead" → send the link to B through a messenger.
2. B: tap the link: CoMaps asks before connecting, as in check 1. If the messenger does not make
   `comaps://` links tappable, copy it, then in CoMaps: Live location → Add contact → "Paste
   invite" (no question then: pasting is the choice).
3. A: "Bob wants to connect. Compare this code with Bob, by phone or in person" → try "Connect
   without comparing" once: the contact shows "Not verified" on A's side, and the share sheet warns
   about it.
4. Optional: close CoMaps on B before A decides, reopen it later: connecting finishes then.

Record: whether the link was tappable in the messenger used.

### 3. A's marker follows within about 5 s

1. A: Live location → Share my location → pick B, "1 hour" → Start. Allow precise location, and
   notifications on Android 13+. A's notification reads "Sharing your live location · With Bob ·
   until …". The map shows "Sharing with 1 person" at the top.
2. B: open the map. A's dot appears within a few seconds: a coloured circle, A's name under it.
   B's own position arrow is drawn above it: with the phones side by side, A's dot can hide under
   it. Move apart, or look for A's name.
3. A: walk or drive. B's dot follows, each move within about 5 s. A logs "location: Live" (B's
   watch signals arrived).
4. B: close CoMaps. After about 2 minutes A goes back to the idle rate (moves of 50 m, or every 5
   minutes).

Record: a few delays between A's move and B's dot moving; whether the dot greys out when updates
stop (after 2 minutes).

### 4. Stop

1. A: tap "Stop" in the notification (or Manage sharing → Stop all).
2. A's notification and chip go away. B's dot greys, then disappears; B's contact no longer says
   "Sharing with you".

Record: how long B took to show the end.

### 5. Revocation, with the test peer

1. Pair A with the test peer: A → Add contact → Share a link instead → copy the link, then
   `peer.py --state peer.json --name Peer join 'comaps://live/pair#…'`, and compare codes.
2. A shares with B and Peer. Run `peer.py --state peer.json follow --minutes 20`: it prints each
   position.
3. A: Manage sharing → Peer → "Stop sharing with Peer". B keeps following A.
4. The peer reports "removed", then keeps trying its old key on everything A publishes. When it
   ends it prints `summary A: N events after the removal, 0 decrypted with the old key`.

Expected: B follows A's new stream after at most about 2 minutes (the new stream stays silent for
30 to 120 s); the peer decrypts 0 events after the removal.

### 6. Time-limited shares end on time

1. A shares with B for 15 min (Share my location → For: 15 min).
2. At the end time the share stops by itself: notification gone, B sees the end.

Record: the difference between the end time shown and the actual end (expect under a minute).

### 7. Two of three relays down

The core moves past failing relays (tests: `Manager_WorksWithTwoOfThreeRelaysDown`, relay pool
tests). On phones, give both the same three relays, the dead ones first so that the listening relay
has to move too: Live location → Settings → relays `wss://dead1.invalid`, `wss://dead2.invalid`,
`wss://nos.lol` (add the two, move them up, remove the other defaults). Identical lists keep relay
consent out of the way. Alternatively, block two default relays for CoMaps with NetGuard or
RethinkDNS.

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
stationary about 0.5–1 %/h and 0.2 MB/h; unwatched and walking 1.5–3.5 %/h and 0.4 MB/h; watched the
whole hour 4–8 %/h and 2.5 MB/h. On Wi-Fi the idle cases drop below 1 %/h. Note whether A moved.

Record: %/h and MB/h for each run; radio active time and GPS time if measured.

### 11. What relays can see, on one screen

Live location → "What relays can see". It fits one screen on a phone, or nearly; it says what relays
can and cannot see (§11.6).

## New code paths to check

- **Changing home relays** (spec §11). With B's CoMaps open, A: Live location settings → add a relay
  (for instance `wss://relay.damus.io`) and remove one default. B is asked once about the new relay;
  allow it. Then B shares with A: A sees B's share. While A shares with B, a change moves the
  share: B's dot carries on after 30–120 s.
- **The daily ratchet** (D16). `adb shell dumpsys jobscheduler | grep -i -A3 comaps.fdroid.debug`
  lists WorkManager's job while the feature is on, and nothing once it is off.

- **No silent sharing.** While sharing: turn off CoMaps' notifications in Android settings → the
  share stops at once on Android 9+ (the system announces the block), otherwise at the next fix
  (2–30 s); the next live location screen or the map says why.
  Swipe the notification away (Android 13+) → it comes back at once. On Android 13+, deny the
  notification permission → sharing does not start, and the share sheet explains.
- **Resume after the process died.** While sharing: `adb shell am kill app.comaps.fdroid.debug`
  does not stop a foreground service, so use `adb shell am force-stop app.comaps.fdroid.debug`,
  then open CoMaps: the map offers "Resume sharing?" with the same people and end time.
- **Relay consent.** On A: Live location settings → Add relay → a relay of your own, then "Move
  up" to make it first. Pair with B or share with B: B is asked about that relay, once ("Live
  updates from A need …"). "Not now" → B's contact shows "Live updates off"; its screen offers
  "Allow …".
- **Settings.** Rename yourself and a contact; hide a contact (its dot goes, and nothing connects
  for it); "Request live updates when viewing" off → A stays idle while B watches.
- **Low battery.** `adb shell dumpsys battery unplug; adb shell dumpsys battery set level 4` while
  sharing → the share stops. `adb shell dumpsys battery reset` afterwards.
- **Deleting.** Live location settings → "Delete all live location data" → contacts gone. Also:
  turn the feature off, choose "Delete all live location data" there.
- **The map chip.** Its place at the top of the map; it hides in route planning and navigation, and
  while a place page is open.
- **Turning it off while sharing.** Settings → turn the switch off → the share stops (B sees the
  end), the notification goes.

## What to send back

For each check: passed or not, the numbers recorded, and for failures the logcat around them and a
screenshot. Layout problems (overlaps, cut-off text, the QR code's size) with a screenshot.

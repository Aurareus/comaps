package app.organicmaps.sdk.livelocation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import app.organicmaps.sdk.livelocation.LiveLocationModels.ConsentRequest;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Contact;
import app.organicmaps.sdk.livelocation.LiveLocationModels.LocationMode;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Pairing;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Position;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Settings;
import app.organicmaps.sdk.livelocation.LiveLocationModels.Sharing;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.json.JSONObject;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Live location (NLL): the Java side reads the core's views as the core writes them. The views were
 * recorded from two C++ peers that paired and shared over a local relay
 * (tools/python/live_location/view_fixtures.py).
 */
public final class LiveLocationModelsTest
{
  private static final Map<String, JSONObject> sViews = new HashMap<>();

  @BeforeClass
  public static void load() throws Exception
  {
    try (InputStream in = LiveLocationModelsTest.class.getResourceAsStream("/live_location/views.jsonl"))
    {
      assertNotNull("views.jsonl", in);
      final BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
      for (String line = reader.readLine(); line != null; line = reader.readLine())
      {
        final JSONObject view = new JSONObject(line);
        sViews.put(view.getString("name"), view.getJSONObject("event"));
      }
    }
  }

  private static JSONObject view(String name)
  {
    final JSONObject view = sViews.get(name);
    assertNotNull(name, view);
    return view;
  }

  @Test
  public void invites()
  {
    final Pairing link = new Pairing(view("pairing_inviter_link"));
    assertTrue(link.inviter);
    assertTrue(link.byLink);
    assertEquals(Pairing.Stage.Waiting, link.stage);
    assertTrue(link.link.startsWith("comaps://live/pair#"));
    assertTrue(link.expiresAt > 1_700_000_000L);
    assertFalse(link.id.isEmpty());

    final Pairing qr = new Pairing(view("pairing_inviter_qr"));
    assertFalse(qr.byLink);
    assertTrue(qr.link.startsWith("comaps://live/pair#"));
    // A QR invite lives 10 minutes, a link a day.
    assertTrue(link.expiresAt - qr.expiresAt > 20 * 3600);
  }

  @Test
  public void codesAndConnection()
  {
    final Pairing joiner = new Pairing(view("pairing_joiner_compare"));
    final Pairing inviter = new Pairing(view("pairing_inviter_compare"));
    assertFalse(joiner.inviter);
    assertEquals(Pairing.Stage.CompareCode, joiner.stage);
    assertEquals(Pairing.Stage.CompareCode, inviter.stage);
    assertTrue(joiner.sas.matches("\\d{3} \\d{3}"));
    assertEquals(joiner.sas, inviter.sas);
    // The joiner learns the inviter's name only with its confirmation.
    assertEquals("", joiner.peerName);
    assertEquals("Alice", inviter.peerName);

    final Pairing connected = new Pairing(view("pairing_joiner_connected"));
    assertEquals(Pairing.Stage.Connected, connected.stage);
    assertEquals("Bob", connected.peerName);
    assertFalse(connected.contactId.isEmpty());
    assertEquals(Pairing.Stage.Waiting, new Pairing(view("pairing_joiner_waiting")).stage);
  }

  @Test
  public void relayConsent()
  {
    final Pairing pairing = new Pairing(view("pairing_needs_consent"));
    assertEquals(Pairing.Stage.NeedsConsent, pairing.stage);
    assertEquals("", pairing.id);
    assertEquals(Collections.singletonList("ws://127.0.0.1:9"), pairing.needsConsent);

    final ConsentRequest request = new ConsentRequest(view("consent_live_updates"));
    assertEquals("ws://127.0.0.1:9", request.url);
    assertEquals("Bob", request.contactName);
    assertEquals(ConsentRequest.Purpose.LiveUpdates, request.purpose);
  }

  @Test
  public void contacts() throws Exception
  {
    final List<Contact> viewer = Contact.list(view("contacts_viewer"));
    assertEquals(1, viewer.size());
    final Contact bob = viewer.get(0);
    assertEquals("Bob", bob.name);
    assertEquals(Long.valueOf(0), bob.sharesWithMeUntil);
    assertNull(bob.iShareUntil);
    assertTrue(bob.verified);
    assertFalse(bob.flagged || bob.waiting || bob.offerRemoval || bob.hidden);
    // Bob's first relay, which live updates need, is not one Alice allowed.
    assertTrue(bob.liveUpdatesOff);
    assertEquals("ws://127.0.0.1:9", bob.liveRelay);
    assertEquals(new Pairing(view("pairing_joiner_compare")).sas, bob.sas);
    // His other relay is Alice's own: something reaches him.
    assertEquals("", bob.blockedRelay);
    assertEquals("teal", bob.color);

    final Contact alice = Contact.list(view("contacts_sharer")).get(0);
    assertEquals("Alice", alice.name);
    assertFalse(alice.liveUpdatesOff);
    assertEquals("", alice.liveRelay);
    assertEquals(Long.valueOf(0), alice.iShareUntil);
    assertNull(alice.sharesWithMeUntil);
    assertFalse(alice.notMoved || alice.moveOverdue);
    assertEquals("", alice.color);
  }

  @Test
  public void blockedContact() throws Exception
  {
    // None of a contact's relays may be used: the core names the one that would do, in the same key.
    final JSONObject view = new JSONObject(view("contacts_viewer").toString());
    final JSONObject entry = view.getJSONArray("contacts").getJSONObject(0);
    assertTrue(entry.has("blocked_relay"));
    entry.put("blocked_relay", "wss://relay.bob.example");
    assertEquals("wss://relay.bob.example", Contact.list(view).get(0).blockedRelay);
  }

  @Test
  public void changedRelays() throws Exception
  {
    // Bob changed his relays while Alice's CoMaps was closed.
    final JSONObject view = view("contacts_not_moved");
    final Contact alice = Contact.list(view).get(0);
    assertEquals("Alice", alice.name);
    assertTrue(alice.notMoved);
    assertFalse(alice.moveOverdue || alice.waiting);

    // 30 days on, the core says so in the same key, which a live recording cannot reach.
    final JSONObject later = new JSONObject(view.toString());
    final JSONObject entry = later.getJSONArray("contacts").getJSONObject(0);
    assertTrue(entry.has("move_overdue"));
    entry.put("move_overdue", true);
    assertTrue(Contact.list(later).get(0).moveOverdue);
  }

  @Test
  public void positions() throws Exception
  {
    final List<Position> positions = Position.list(view("positions"));
    assertEquals(1, positions.size());
    final Position bob = positions.get(0);
    assertEquals("Bob", bob.name);
    assertEquals(Contact.list(view("contacts_viewer")).get(0).id, bob.contactId);
    assertEquals(52.5200066, bob.lat, 0);
    assertEquals(13.404954, bob.lon, 0);
    assertEquals(8.0, bob.accuracy, 0);
    assertTrue(bob.timeMs > 1_700_000_000_000L);
    assertFalse(bob.stale);
    // Bob shares with a colour, at 10 % battery.
    assertTrue(bob.low);
    assertEquals("teal", bob.color);
  }

  @Test
  public void sharing() throws Exception
  {
    final Sharing active = new Sharing(view("sharing_active"));
    assertTrue(active.active);
    assertEquals(1, active.recipients.size());
    assertEquals(new Pairing(view("pairing_inviter_connected")).contactId, active.recipients.get(0).contactId);
    assertEquals(0, active.recipients.get(0).until);
    assertTrue(active.resumable.isEmpty());

    final Sharing stopped = new Sharing(view("sharing_stopped"));
    assertFalse(stopped.active);
    assertTrue(stopped.recipients.isEmpty());

    assertEquals(LocationMode.Idle, LocationMode.valueOf(view("location_idle").getString("mode")));
    assertEquals(LocationMode.Live, LocationMode.valueOf(view("location_live").getString("mode")));
  }

  @Test
  public void settings() throws Exception
  {
    final Settings settings = new Settings(view("settings"));
    assertTrue(settings.readable);
    assertEquals("Alice", settings.name);
    assertFalse(settings.homeRelays.isEmpty());
    assertEquals(1, settings.approved.size());
    assertEquals("ws://127.0.0.1:9", settings.approved.get(0)[0]);
    assertEquals("Bob", settings.approved.get(0)[1]);
    assertEquals(1, settings.declined.size());
    assertEquals("ws://127.0.0.1:8", settings.declined.get(0)[0]);
    assertEquals("Carol", settings.declined.get(0)[1]);
    assertEquals(3, settings.defaultRelays.size());
    assertEquals("wss://nos.lol", settings.defaultRelays.get(0));
    assertTrue(settings.requestLive && settings.allowLive);
    assertEquals(5, settings.lowBatteryStop);
    assertEquals("purple", settings.color);
    // CoMaps' bookmark colours without the greys, in their order.
    assertEquals(14, settings.dotColors.size());
    assertEquals("red", settings.dotColors.get(0).name);
    assertEquals(0xE51B23, settings.dotColors.get(0).rgb);
    assertEquals("brown", settings.dotColors.get(13).name);

    // A store that cannot be read: the same view, flagged.
    final JSONObject unreadable = new JSONObject(view("settings").toString());
    unreadable.put("readable", false);
    assertFalse(new Settings(unreadable).readable);
  }
}

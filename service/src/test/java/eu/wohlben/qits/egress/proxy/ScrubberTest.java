package eu.wohlben.qits.egress.proxy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.http.HttpMethod;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/** The scrubber alone: its forms, its headers, and the streaming window at every split point. */
class ScrubberTest {

  static final String SECRET = "s3cr3t value/with+chars";

  final Scrubber scrubber = Scrubber.of(SECRET);

  @Test
  void everyFormIsReplacedInText() {
    String base64 = Base64.getEncoder().encodeToString(SECRET.getBytes(StandardCharsets.UTF_8));
    String url = URLEncoder.encode(SECRET, StandardCharsets.UTF_8);
    String text =
        "raw=" + SECRET + " b64=" + base64 + " url=" + url + " pct=" + url.replace("+", "%20");
    String scrubbed = scrubber.scrub(text);
    assertEquals(
        "raw=[redacted] b64=[redacted] url=[redacted] pct=[redacted]",
        scrubbed.replace("[redacted]==", "[redacted]").replace("[redacted]=", "[redacted]"));
    assertFalse(scrubbed.contains(SECRET));
  }

  @Test
  void headerValuesAreScrubbedLocationIncluded() {
    MultiMap headers =
        MultiMap.caseInsensitiveMultiMap()
            .add("Location", "https://example.test/cb?key=" + URLEncoder.encode(SECRET, StandardCharsets.UTF_8))
            .add("X-Echo", "Bearer " + SECRET)
            .add("X-Plain", "nothing here");
    scrubber.scrub(headers);
    assertEquals("https://example.test/cb?key=[redacted]", headers.get("Location"));
    assertEquals("Bearer [redacted]", headers.get("X-Echo"));
    assertEquals("nothing here", headers.get("X-Plain"));
  }

  @Test
  void aSecretSplitAtEveryPointIsStillCaught() {
    String body = "before " + SECRET + " middle " + SECRET + " after";
    byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
    for (int cut = 0; cut <= bytes.length; cut++) {
      for (int second = cut; second <= bytes.length; second += 7) {
        Scrubber.Window window = scrubber.window();
        StringBuilder out = new StringBuilder();
        out.append(window.push(Buffer.buffer(java.util.Arrays.copyOfRange(bytes, 0, cut))));
        out.append(window.push(Buffer.buffer(java.util.Arrays.copyOfRange(bytes, cut, second))));
        out.append(
            window.push(Buffer.buffer(java.util.Arrays.copyOfRange(bytes, second, bytes.length))));
        out.append(window.finish());
        assertEquals("before [redacted] middle [redacted] after", out.toString(), "cut " + cut);
      }
    }
  }

  @Test
  void aByteAtATimeIsStillCaughtAndTheWindowStaysSmall() {
    String body = "x".repeat(50) + SECRET + "y".repeat(50);
    Scrubber.Window window = scrubber.window();
    StringBuilder out = new StringBuilder();
    for (byte b : body.getBytes(StandardCharsets.UTF_8)) {
      out.append(window.push(Buffer.buffer(new byte[] {b})));
      assertTrue(window.held() < scrubber.longest(), "held " + window.held());
    }
    out.append(window.finish());
    assertEquals("x".repeat(50) + "[redacted]" + "y".repeat(50), out.toString());
  }

  @Test
  void textThatCannotStartAFormIsReleasedAtOnce() {
    Scrubber.Window window = scrubber.window();
    assertEquals("data: one\n\n", window.push(Buffer.buffer("data: one\n\n")).toString());
    assertEquals(0, window.held());
    // The tail could be the secret's start: held back, and released when it turns out not to be.
    assertEquals("data: ", window.push(Buffer.buffer("data: s3c")).toString());
    assertEquals(3, window.held());
    assertEquals("s3cond\n\n", window.push(Buffer.buffer("ond\n\n")).toString());
  }

  @Test
  void onlyAnswersWithABodyAreScrubbedAsBodies() {
    assertTrue(ResponseScrub.carriesBody(HttpMethod.GET, 200));
    assertFalse(ResponseScrub.carriesBody(HttpMethod.HEAD, 200));
    assertFalse(ResponseScrub.carriesBody(HttpMethod.GET, 204));
    assertFalse(ResponseScrub.carriesBody(HttpMethod.GET, 304));
    assertFalse(ResponseScrub.carriesBody(HttpMethod.GET, 101));
  }

  @Test
  void theScrubberNamesNoSecret() {
    assertEquals("Scrubber", scrubber.toString());
  }
}

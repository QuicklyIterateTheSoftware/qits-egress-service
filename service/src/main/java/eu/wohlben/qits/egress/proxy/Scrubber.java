package eu.wohlben.qits.egress.proxy;

import io.vertx.core.MultiMap;
import io.vertx.core.buffer.Buffer;
import java.io.ByteArrayOutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * <b>Takes one route's secret back out of what the upstream answers</b>: a third party that echoes
 * the credential (an error that quotes the request, a redirect carrying it, a "your key is …"
 * page) must not hand it to the calling application, which is exactly who may not hold it.
 *
 * <p>What is replaced with {@value #REDACTED}: the secret as it was injected, its base64 (standard
 * and URL alphabet, unpadded, so the padded spelling is covered too) and its URL-encoded forms
 * ({@code +} and {@code %20} for a space). Replaced in every response header value — {@code
 * Location} included — in the body, streamed through {@link Window} with a carry-over of at most
 * {@code len(longest form) - 1} bytes, and in every error body the gateway writes itself.
 *
 * <p>What it cannot see: a body the upstream compressed (the request forces {@code
 * Accept-Encoding: identity}, and an answer that is encoded anyway is refused — see {@link
 * ResponseScrub}), a form not listed here (the secret hex-encoded, split by an encoder, inside
 * another base64 string at an offset that is not a multiple of three), and WebSocket frames, which
 * are spliced as bytes.
 *
 * <p>Immutable and holds the secret's forms: never logged, never {@code toString}'d with them.
 */
final class Scrubber {

  static final String REDACTED = "[redacted]";

  private static final byte[] REDACTED_BYTES = REDACTED.getBytes(StandardCharsets.UTF_8);

  /** Longest first, so a form that contains another is replaced whole. */
  private final List<byte[]> forms;

  private final List<String> textForms;

  private final int longest;

  private Scrubber(List<String> forms) {
    this.textForms = forms;
    this.forms = forms.stream().map(f -> f.getBytes(StandardCharsets.UTF_8)).toList();
    this.longest = this.forms.stream().mapToInt(f -> f.length).max().orElse(0);
  }

  /** The scrubber for one secret value. */
  static Scrubber of(String secret) {
    if (secret == null || secret.isEmpty()) {
      throw new IllegalArgumentException("no secret to scrub");
    }
    byte[] raw = secret.getBytes(StandardCharsets.UTF_8);
    Set<String> forms = new LinkedHashSet<>();
    forms.add(secret);
    forms.add(Base64.getEncoder().withoutPadding().encodeToString(raw));
    forms.add(Base64.getUrlEncoder().withoutPadding().encodeToString(raw));
    String encoded = URLEncoder.encode(secret, StandardCharsets.UTF_8);
    forms.add(encoded);
    forms.add(encoded.replace("+", "%20"));
    List<String> sorted = new ArrayList<>(forms);
    sorted.removeIf(String::isEmpty);
    sorted.sort(Comparator.comparingInt(String::length).reversed());
    return new Scrubber(List.copyOf(sorted));
  }

  /** The longest form's length in bytes: the window is one less. */
  int longest() {
    return longest;
  }

  /** One text — a header value, an error body — with every form replaced. */
  String scrub(String text) {
    if (text == null || text.isEmpty()) {
      return text;
    }
    String scrubbed = text;
    for (String form : textForms) {
      scrubbed = scrubbed.replace(form, REDACTED);
    }
    return scrubbed;
  }

  /** Every header value, in place. Names are left alone: a name is not where a value goes. */
  void scrub(MultiMap headers) {
    List<Map.Entry<String, String>> copy = new ArrayList<>();
    boolean changed = false;
    for (Map.Entry<String, String> header : headers) {
      String scrubbed = scrub(header.getValue());
      changed |= !scrubbed.equals(header.getValue());
      copy.add(Map.entry(header.getKey(), scrubbed));
    }
    if (!changed) {
      return;
    }
    headers.clear();
    copy.forEach(header -> headers.add(header.getKey(), header.getValue()));
  }

  /** A fresh streaming window over one body. */
  Window window() {
    return new Window();
  }

  /**
   * <b>The streaming half</b>: bytes in, scrubbed bytes out, holding back only what could still be
   * the beginning of a form. A byte is released as soon as no form can start at it any more, so an
   * SSE event's last line is not held for the next one unless it ends in a form's first bytes; at
   * most {@code longest() - 1} bytes are ever held.
   */
  final class Window {

    private byte[] carry = new byte[0];

    /** Scrub one chunk; what can be released now. */
    Buffer push(Buffer chunk) {
      byte[] in = chunk.getBytes();
      byte[] data;
      if (carry.length == 0) {
        data = in;
      } else {
        data = new byte[carry.length + in.length];
        System.arraycopy(carry, 0, data, 0, carry.length);
        System.arraycopy(in, 0, data, carry.length, in.length);
      }
      return Buffer.buffer(scan(data, false));
    }

    /** The end of the body: whatever is still held, scrubbed. */
    Buffer finish() {
      byte[] rest = carry;
      carry = new byte[0];
      return Buffer.buffer(scan(rest, true));
    }

    /** How many bytes are held back right now. */
    int held() {
      return carry.length;
    }

    private byte[] scan(byte[] data, boolean last) {
      ByteArrayOutputStream out = new ByteArrayOutputStream(data.length + 16);
      int i = 0;
      int start = 0;
      while (i < data.length) {
        byte[] whole = matchAt(data, i);
        if (whole != null) {
          out.write(data, start, i - start);
          out.write(REDACTED_BYTES, 0, REDACTED_BYTES.length);
          i += whole.length;
          start = i;
          continue;
        }
        if (!last && data.length - i < longest && prefixAt(data, i)) {
          break;
        }
        i++;
      }
      out.write(data, start, i - start);
      carry = last ? new byte[0] : java.util.Arrays.copyOfRange(data, i, data.length);
      return out.toByteArray();
    }

    /** The longest form that starts at {@code i} and fits, or null. */
    private byte[] matchAt(byte[] data, int i) {
      for (byte[] form : forms) {
        if (data.length - i >= form.length && regionMatches(data, i, form, form.length)) {
          return form;
        }
      }
      return null;
    }

    /** Whether the bytes from {@code i} to the end are the beginning of some form. */
    private boolean prefixAt(byte[] data, int i) {
      int remaining = data.length - i;
      for (byte[] form : forms) {
        if (form.length > remaining && regionMatches(data, i, form, remaining)) {
          return true;
        }
      }
      return false;
    }

    private static boolean regionMatches(byte[] data, int at, byte[] form, int length) {
      for (int k = 0; k < length; k++) {
        if (data[at + k] != form[k]) {
          return false;
        }
      }
      return true;
    }
  }

  @Override
  public String toString() {
    return "Scrubber";
  }
}

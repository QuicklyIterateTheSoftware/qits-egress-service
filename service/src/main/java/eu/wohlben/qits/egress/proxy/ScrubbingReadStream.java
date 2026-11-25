package eu.wohlben.qits.egress.proxy;

import io.vertx.core.Handler;
import io.vertx.core.buffer.Buffer;
import io.vertx.core.streams.ReadStream;

/**
 * A response body with a route's secret taken out on the way through ({@link Scrubber.Window}),
 * chunk by chunk: nothing is buffered beyond the window, so an event stream stays a stream. Flow
 * control is the source's — pause, resume and fetch go straight to it — and a chunk that is held
 * back whole is simply not delivered yet.
 */
final class ScrubbingReadStream implements ReadStream<Buffer> {

  private final ReadStream<Buffer> source;

  private final Scrubber.Window window;

  private Handler<Buffer> handler;

  private Handler<Void> endHandler;

  ScrubbingReadStream(ReadStream<Buffer> source, Scrubber scrubber) {
    this.source = source;
    this.window = scrubber.window();
  }

  @Override
  public ScrubbingReadStream exceptionHandler(Handler<Throwable> handler) {
    source.exceptionHandler(handler);
    return this;
  }

  @Override
  public ScrubbingReadStream handler(Handler<Buffer> handler) {
    this.handler = handler;
    if (handler == null) {
      source.handler(null);
    } else {
      source.handler(
          chunk -> {
            Buffer out = window.push(chunk);
            Handler<Buffer> to = this.handler;
            if (out.length() > 0 && to != null) {
              to.handle(out);
            }
          });
    }
    return this;
  }

  @Override
  public ScrubbingReadStream endHandler(Handler<Void> endHandler) {
    this.endHandler = endHandler;
    if (endHandler == null) {
      source.endHandler(null);
    } else {
      source.endHandler(
          v -> {
            Buffer rest = window.finish();
            Handler<Buffer> to = this.handler;
            if (rest.length() > 0 && to != null) {
              to.handle(rest);
            }
            Handler<Void> end = this.endHandler;
            if (end != null) {
              end.handle(null);
            }
          });
    }
    return this;
  }

  @Override
  public ScrubbingReadStream pause() {
    source.pause();
    return this;
  }

  @Override
  public ScrubbingReadStream resume() {
    source.resume();
    return this;
  }

  @Override
  public ScrubbingReadStream fetch(long amount) {
    source.fetch(amount);
    return this;
  }
}

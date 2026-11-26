package eu.wohlben.qits.egress.proxy;

import static eu.wohlben.qits.egress.proxy.ProxyWire.applicationToken;
import static org.junit.jupiter.api.Assertions.assertFalse;

import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.vertx.http.runtime.filters.GracefulShutdownFilter;
import io.quarkus.vertx.http.runtime.filters.QuarkusRequestWrapper;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.WebSocket;
import io.vertx.core.http.WebSocketClient;
import io.vertx.core.http.WebSocketConnectOptions;
import jakarta.inject.Inject;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * <b>A closed forward leaves Quarkus' HTTP drain</b> ({@link DrainCount}, qits-2660). {@code
 * toWebSocket()} hands the response to the websocket and no response handler of it runs again, so
 * before the fix every forward ever opened stayed counted and a shutdown waited out its whole
 * {@code quarkus.shutdown.timeout} (5 minutes; seen as a test profile switch after {@link
 * ForwardDoorTest} taking 300 s). The real {@link ForwardDoor} serves behind a {@link
 * GracefulShutdownFilter} of the test's own, each request wrapped as Quarkus' root handler wraps it;
 * the drain is started the way Quarkus does — {@code preShutdown}, then {@code shutdown} with a
 * notification — and must end once the forward is closed.
 */
@QuarkusTest
class ForwardDrainTest {

  @Inject Vertx vertx;

  @Inject ForwardDoor door;

  GracefulShutdownFilter filter;

  HttpServer server;

  @BeforeEach
  void listen() throws Exception {
    filter = new GracefulShutdownFilter();
    filter.next(door::handle);
    server =
        vertx
            .createHttpServer()
            .requestHandler(
                request -> filter.handle(new QuarkusRequestWrapper(request, (cookie, r) -> {})))
            .listen(0, "127.0.0.1")
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
  }

  @AfterEach
  void close() throws Exception {
    server.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
  }

  @Test
  void theDrainEndsOnceTheForwardIsClosed() throws Exception {
    WebSocketClient client = vertx.createWebSocketClient();
    WebSocket socket =
        client
            .connect(
                new WebSocketConnectOptions()
                    .setHost("127.0.0.1")
                    .setPort(server.actualPort())
                    .setURI(ForwardDoor.PATH)
                    .addHeader("Authorization", "Bearer " + applicationToken()))
            .toCompletionStage()
            .toCompletableFuture()
            .get(10, TimeUnit.SECONDS);
    CompletableFuture<Void> closed = new CompletableFuture<>();
    socket.closeHandler(v -> closed.complete(null));

    CompletableFuture<Void> drained = new CompletableFuture<>();
    filter.preShutdown(() -> {});
    filter.shutdown(() -> drained.complete(null));
    Thread.sleep(300);
    assertFalse(drained.isDone(), "an open forward is a request in flight");

    socket.close().toCompletionStage().toCompletableFuture().get(10, TimeUnit.SECONDS);
    closed.get(10, TimeUnit.SECONDS);
    drained.get(10, TimeUnit.SECONDS);
    client.close();
  }
}

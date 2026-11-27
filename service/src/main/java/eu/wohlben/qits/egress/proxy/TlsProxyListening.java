package eu.wohlben.qits.egress.proxy;

/**
 * The TLS proxy listener (8082, qits-2759) opened on {@code port}: a synchronous CDI event, fired
 * once, on the event loop. An observer schedules, never blocks.
 */
public record TlsProxyListening(int port) {}

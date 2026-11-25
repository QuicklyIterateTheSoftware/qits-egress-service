package eu.wohlben.qits.egress.proxy;

import jakarta.annotation.PostConstruct;
import jakarta.enterprise.context.ApplicationScoped;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jboss.logging.Logger;

/**
 * <b>The secrets routes inject</b>: every {@code QITS_EGRESS_SECRET_<NAME>} this process was started
 * with, read ONCE at boot and held in memory. A deployment supplies them as secret settings of the
 * application {@code qits-egress} (pd_setting rows, {@code secret: true}), which qits-deployments
 * injects as environment variables; a route's {@code secret: HETZNER_DNS} is the value of {@code
 * QITS_EGRESS_SECRET_HETZNER_DNS}.
 *
 * <p>Read through MicroProfile Config, whose environment source lists every variable by its own
 * name, so a suite supplies one as a config key of the same name.
 *
 * <p><b>A value never leaves this class except into the one outbound header it is for.</b> It is
 * never logged (the boot line names the secrets, not their values), never in an error body, never
 * in an audit line, and {@link #toString()} names nothing at all. A secret that is not here
 * answers the caller 502 "secret not configured".
 */
@ApplicationScoped
public class SecretStore {

  private static final Logger LOG = Logger.getLogger(SecretStore.class);

  static final String PREFIX = "QITS_EGRESS_SECRET_";

  private Map<String, String> values = Map.of();

  @PostConstruct
  void load() {
    values = read(ConfigProvider.getConfig());
    LOG.infof("secrets held for routes: %s", names());
  }

  static Map<String, String> read(Config config) {
    Map<String, String> found = new TreeMap<>();
    for (String property : config.getPropertyNames()) {
      if (property.startsWith(PREFIX) && property.length() > PREFIX.length()) {
        config
            .getOptionalValue(property, String.class)
            .filter(value -> !value.isBlank())
            .ifPresent(value -> found.put(property.substring(PREFIX.length()), value));
      }
    }
    return Map.copyOf(found);
  }

  /** The value of the secret {@code name}, if this process holds it. */
  public Optional<String> value(String name) {
    return name == null ? Optional.empty() : Optional.ofNullable(values.get(name));
  }

  /** The names held, for the boot line. Never the values. */
  public Set<String> names() {
    return new java.util.TreeSet<>(values.keySet());
  }

  @Override
  public String toString() {
    return "SecretStore";
  }
}

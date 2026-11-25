package eu.wohlben.qits.egress;

import eu.wohlben.qits.archrules.DatasourceBaselineRules;
import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

/**
 * Every postgresql datasource this service boots — today `domain`'s egress store alone — carries
 * the three-line resilience block. A {@code @QuarkusTest}, because the rule has to judge the merged
 * configuration the application actually starts with.
 */
@QuarkusTest
public class DatasourceBaselineTest {

  @Test
  public void everyPostgresDatasourceCarriesTheBaseline() {
    DatasourceBaselineRules.assertBaseline();
  }
}

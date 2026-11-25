package eu.wohlben.qits.egress;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;

import io.agroal.api.AgroalDataSource;
import io.quarkus.agroal.DataSource;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The service boots, migrates its store, and answers the readiness probe the deployer gates on
 * ({@code health_path: /egress/q/health/ready}).
 */
@QuarkusTest
class HealthTest {

  @Inject
  @DataSource("egress")
  AgroalDataSource egress;

  @Test
  void readinessAnswersUp() {
    given()
        .when()
        .get("/egress/q/health/ready")
        .then()
        .statusCode(200)
        .body("status", equalTo("UP"))
        .body("checks.name", hasItem("Database connections health check"));
  }

  @Test
  void theGrantTableIsMigrated() throws Exception {
    List<String> columns = new ArrayList<>();
    try (Connection db = egress.getConnection();
        ResultSet found =
            db.createStatement()
                .executeQuery(
                    "select column_name from information_schema.columns where table_schema ="
                        + " 'egress' and table_name = 'egress_grant_table' order by"
                        + " ordinal_position")) {
      while (found.next()) {
        columns.add(found.getString(1));
      }
    }
    org.junit.jupiter.api.Assertions.assertEquals(
        List.of("id", "version", "body", "received_at", "received_from"), columns);
  }
}

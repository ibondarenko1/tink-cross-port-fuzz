// java-runner reads a JWK Set from stdin, calls
// com.google.crypto.tink.jwt.JwkSetConverter.toPublicKeysetHandle,
// and emits a single JSON line describing the verdict.
//
// Output schema:
//   {"verdict":"ACCEPT|REJECT_TINK|REJECT_OTHER",
//    "error_class":"<java-exception-class-name>",
//    "error_msg":"<truncated>",
//    "keyset_shape":"<opaque>"}
package com.ibondarenko1.tinkfuzz;

import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.jwt.JwkSetConverter;
import com.google.crypto.tink.jwt.JwtPublicKeyVerify;
import com.google.crypto.tink.jwt.JwtSignatureConfig;
import com.google.crypto.tink.jwt.JwtValidator;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

public class JavaRunner {

  public static void main(String[] args) {
    if (args.length > 0 && "--compat".equals(args[0])) {
      int exitCode = runCompat();
      if (exitCode != 0) {
        System.exit(exitCode);
      }
      return;
    }

    // Preserve the historical single-JWK-set fuzzing mode byte-for-byte.
    try {
      JwtSignatureConfig.register();
    } catch (GeneralSecurityException e) {
      // Best-effort; tink-java sometimes already-registered in test contexts.
    }

    String input;
    try {
      input = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      emitVerdict("REJECT_OTHER", "stdin-read", e.getMessage(), null);
      System.exit(1);
      return;
    }

    try {
      KeysetHandle handle = JwkSetConverter.toPublicKeysetHandle(input);
      emitVerdict("ACCEPT", null, null, "<opaque>");
    } catch (GeneralSecurityException | IOException e) {
      emitVerdict("REJECT_TINK", e.getClass().getSimpleName(), truncate(e.getMessage()), null);
    } catch (RuntimeException e) {
      // Per the project README, RuntimeException from a Tink public API is a
      // contract-violation finding (REJECT_OTHER). The duplicate-key class
      // is what surfaced here for the tink-java JwkSetConverter line-97
      // NullPointerException case.
      emitVerdict("REJECT_OTHER", e.getClass().getSimpleName(), truncate(e.getMessage()), null);
    }
  }

  /** Runs the bounded release compatibility consumer. */
  private static int runCompat() {
    String input;
    try {
      input = new String(System.in.readAllBytes(), StandardCharsets.UTF_8);
    } catch (IOException e) {
      emitCompatError("unable to read compatibility request");
      return 2;
    }

    try {
      JsonElement parsed = JsonParser.parseString(input);
      if (!parsed.isJsonObject()) {
        throw new IllegalArgumentException("request must be an object");
      }
      JsonObject request = parsed.getAsJsonObject();
      String operation = requiredString(request, "operation");
      if (!"verify".equals(operation)) {
        throw new IllegalArgumentException("operation must be verify");
      }
      JsonElement checksElement = request.get("checks");
      if (checksElement == null || !checksElement.isJsonArray()) {
        throw new IllegalArgumentException("checks must be an array");
      }

      // Tink Java requires the JWT registry to be initialized before the
      // public JWK converter or primitive lookup is used.  A registration
      // failure is a process/setup error, never a rejected signature.
      JwtSignatureConfig.register();

      List<JsonObject> results = new ArrayList<>();
      JsonArray checks = checksElement.getAsJsonArray();
      for (JsonElement checkElement : checks) {
        if (!checkElement.isJsonObject()) {
          throw new IllegalArgumentException("each check must be an object");
        }
        results.add(verifyCompatCheck(checkElement.getAsJsonObject()));
      }

      JsonObject response = new JsonObject();
      response.addProperty("version", tinkVersion());
      response.addProperty("runtime", runtimeName());
      JsonArray resultArray = new JsonArray();
      for (JsonObject result : results) {
        resultArray.add(result);
      }
      response.add("results", resultArray);
      System.out.println(new Gson().toJson(response));
      return 0;
    } catch (RuntimeException e) {
      // The request parser and schema checks are not signature decisions.
      // Do not echo exception text because a parser message can contain an
      // input fragment supplied by the caller.
      emitCompatError("invalid compatibility request");
      return 2;
    } catch (GeneralSecurityException e) {
      emitCompatError("JWT registry setup failed");
      return 2;
    }
  }

  private static JsonObject verifyCompatCheck(JsonObject check) {
    String id = requiredString(check, "id");
    String compact = requiredString(check, "compact");
    String issuer = requiredString(check, "issuer");
    String audience = optionalString(check, "audience");
    long now = requiredLong(check, "now");
    JsonElement jwksElement = check.get("jwks");
    if (jwksElement == null || !jwksElement.isJsonObject()) {
      return compatResult(id, "error", "key setup failed");
    }

    JsonObject result = new JsonObject();
    result.addProperty("id", id);
    KeysetHandle handle;
    JwtPublicKeyVerify verifier;
    JwtValidator validator;
    try {
      handle = JwkSetConverter.toPublicKeysetHandle(jwksElement.toString());
      verifier = handle.getPrimitive(
          RegistryConfiguration.get(), JwtPublicKeyVerify.class);
      JwtValidator.Builder validatorBuilder = JwtValidator.newBuilder()
          .setClock(Clock.fixed(Instant.ofEpochSecond(now), ZoneOffset.UTC))
          .expectIssuer(issuer);
      if (audience != null) {
        validatorBuilder.expectAudience(audience);
      }
      validator = validatorBuilder.build();
    } catch (GeneralSecurityException | IOException e) {
      // Import, primitive registration and validator construction are setup
      // failures.  They must not be confused with a negative signature.
      return compatResult(id, "error", "key setup failed");
    } catch (RuntimeException e) {
      return compatResult(id, "error", "key setup runtime failure");
    }
    try {
      verifier.verifyAndDecode(compact, validator);
      result.addProperty("outcome", "verified");
    } catch (GeneralSecurityException e) {
      // Once the keyset and validator are constructed, Tink reports bad
      // signatures, malformed tokens, expired tokens and issuer mismatches as
      // verification failures.  They are expected negative vectors.
      result.addProperty("outcome", "rejected");
    } catch (RuntimeException e) {
      // A runtime exception from a public verification API is an adapter
      // failure, not evidence that a signature was rejected.
      result.addProperty("outcome", "error");
      result.addProperty("detail", "verification runtime failure");
    }
    return result;
  }

  private static JsonObject compatResult(String id, String outcome, String detail) {
    JsonObject result = new JsonObject();
    result.addProperty("id", id);
    result.addProperty("outcome", outcome);
    if (detail != null) {
      result.addProperty("detail", detail);
    }
    return result;
  }

  private static String requiredString(JsonObject object, String name) {
    JsonElement value = object.get(name);
    if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
      throw new IllegalArgumentException(name + " must be a string");
    }
    String text = value.getAsString();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be empty");
    }
    return text;
  }

  private static String optionalString(JsonObject object, String name) {
    JsonElement value = object.get(name);
    if (value == null || value.isJsonNull()) {
      return null;
    }
    if (!value.isJsonPrimitive() || !value.getAsJsonPrimitive().isString()) {
      throw new IllegalArgumentException(name + " must be a string");
    }
    String text = value.getAsString();
    if (text.isEmpty()) {
      throw new IllegalArgumentException(name + " must not be empty");
    }
    return text;
  }

  private static long requiredLong(JsonObject object, String name) {
    JsonElement value = object.get(name);
    if (value == null || !value.isJsonPrimitive() || !value.getAsJsonPrimitive().isNumber()) {
      throw new IllegalArgumentException(name + " must be an integer");
    }
    String text = value.getAsString();
    if (!text.matches("-?[0-9]+")) {
      throw new IllegalArgumentException(name + " must be an integer");
    }
    try {
      return Long.parseLong(text);
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(name + " is out of range");
    }
  }

  private static String tinkVersion() {
    // The Maven dependency plugin writes the resolved dependency graph into
    // our own namespace.  The upstream Tink single-jar does not carry Maven
    // metadata, so do not fabricate dependency-owned pom.properties.
    try (InputStream stream = JavaRunner.class.getClassLoader().getResourceAsStream(
        "META-INF/tink-compat/dependencies.txt")) {
      if (stream != null) {
        String graph = new String(stream.readAllBytes(), StandardCharsets.UTF_8);
        String gavPrefix = "com.google.crypto.tink:tink:jar:";
        for (String line : graph.split("\\R")) {
          int start = line.indexOf(gavPrefix);
          if (start < 0) {
            continue;
          }
          String version = line.substring(start + gavPrefix.length());
          int end = version.indexOf(':');
          if (end >= 0) {
            version = version.substring(0, end);
          }
          version = version.trim();
          if (!version.isEmpty()) {
            return version.startsWith("v") ? version.substring(1) : version;
          }
        }
      }
    } catch (IOException e) {
      // Missing provenance is reported explicitly below.
    }
    return "unknown";
  }

  private static String runtimeName() {
    return "java " + System.getProperty("java.version") + " "
        + System.getProperty("os.name") + "/" + System.getProperty("os.arch");
  }

  private static void emitCompatError(String detail) {
    JsonObject error = new JsonObject();
    error.addProperty("error", detail);
    System.out.println(new Gson().toJson(error));
  }

  private static String truncate(String s) {
    if (s == null) return null;
    return s.length() <= 200 ? s : s.substring(0, 200);
  }

  private static void emitVerdict(String verdict, String errClass, String errMsg, String shape) {
    StringBuilder sb = new StringBuilder("{\"verdict\":\"").append(verdict).append("\"");
    if (errClass != null) sb.append(",\"error_class\":").append(jsonString(errClass));
    if (errMsg != null) sb.append(",\"error_msg\":").append(jsonString(errMsg));
    if (shape != null) sb.append(",\"keyset_shape\":").append(jsonString(shape));
    sb.append("}");
    System.out.println(sb);
  }

  private static String jsonString(String s) {
    StringBuilder sb = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '\\': sb.append("\\\\"); break;
        case '"':  sb.append("\\\""); break;
        case '\n': sb.append("\\n"); break;
        case '\r': sb.append("\\r"); break;
        case '\t': sb.append("\\t"); break;
        default:
          if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
          else sb.append(c);
      }
    }
    return sb.append("\"").toString();
  }
}

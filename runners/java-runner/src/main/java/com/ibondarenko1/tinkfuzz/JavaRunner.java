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

import com.google.crypto.tink.KeysetHandle;
import com.google.crypto.tink.jwt.JwkSetConverter;
import com.google.crypto.tink.jwt.JwtSignatureConfig;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

public class JavaRunner {

  public static void main(String[] args) {
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

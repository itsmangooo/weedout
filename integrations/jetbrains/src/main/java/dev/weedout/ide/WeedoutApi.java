package dev.weedout.ide;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

final class WeedoutApi {
    private final String baseUrl;
    private final HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(15)).build();

    WeedoutApi(String baseUrl) { this.baseUrl = baseUrl.replaceAll("/$", ""); }

    JsonObject startAuth(String label) throws IOException, InterruptedException {
        return json("/api/cli-auth/start", "POST", null, "{\"device_label\":" + quote(label) + "}", "application/json");
    }

    JsonObject pollAuth(String deviceCode) throws IOException, InterruptedException {
        return json("/api/cli-auth/poll", "POST", null, "{\"device_code\":" + quote(deviceCode) + "}", "application/json");
    }

    JsonObject createProject(String machineToken, String name, String filename, String content) throws IOException, InterruptedException {
        String body = "{\"name\":" + quote(name) + ",\"filename\":" + quote(filename) +
            ",\"content\":" + quote(content) + ",\"scope\":\"manage\"}";
        return json("/api/account/projects", "POST", machineToken, body, "application/json");
    }

    void deleteProject(String machineToken, int id) throws IOException, InterruptedException {
        json("/api/account/projects/" + id, "DELETE", machineToken, "", "application/json");
    }

    List<Finding> scan(String projectKey, String filename, byte[] manifest, byte[] policy) throws IOException, InterruptedException {
        String boundary = "weedout-" + UUID.randomUUID();
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        part(body, boundary, "manifest", filename, manifest);
        if (policy != null) part(body, boundary, "policy", ".weedout.yml", policy);
        body.write(("--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8));
        request("/api/v1/scan", "POST", projectKey, body.toByteArray(), "multipart/form-data; boundary=" + boundary);
        JsonObject payload = json("/api/v1/findings?show=open&limit=200", "GET", projectKey, "", "application/json");
        return findings(payload.getAsJsonArray("findings"));
    }

    private JsonObject json(String path, String method, String token, String body, String contentType) throws IOException, InterruptedException {
        return JsonParser.parseString(request(path, method, token, body.getBytes(StandardCharsets.UTF_8), contentType)).getAsJsonObject();
    }

    private String request(String path, String method, String token, byte[] body, String contentType) throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(baseUrl + path))
            .timeout(Duration.ofSeconds(60)).header("Accept", "application/json");
        if (token != null && !token.isBlank()) builder.header("Authorization", "Bearer " + token);
        if (!bodyIsEmpty(method)) builder.header("Content-Type", contentType);
        builder.method(method, bodyIsEmpty(method) ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofByteArray(body));
        HttpResponse<String> response = client.send(builder.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            String message = "Request failed (" + response.statusCode() + ")";
            try {
                JsonElement detail = JsonParser.parseString(response.body()).getAsJsonObject().get("detail");
                if (detail != null && detail.isJsonObject() && detail.getAsJsonObject().has("message")) message = detail.getAsJsonObject().get("message").getAsString();
                else if (detail != null && detail.isJsonPrimitive()) message = detail.getAsString();
            } catch (RuntimeException ignored) { }
            throw new IOException(message);
        }
        return response.body().isBlank() ? "{}" : response.body();
    }

    private static boolean bodyIsEmpty(String method) { return method.equals("GET") || method.equals("DELETE"); }

    private static void part(ByteArrayOutputStream out, String boundary, String name, String filename, byte[] value) throws IOException {
        out.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"" + name + "\"; filename=\"" + filename + "\"\r\n" +
            "Content-Type: text/plain; charset=utf-8\r\n\r\n").getBytes(StandardCharsets.UTF_8));
        out.write(value);
        out.write("\r\n".getBytes(StandardCharsets.UTF_8));
    }

    private static List<Finding> findings(JsonArray array) {
        List<Finding> result = new ArrayList<>();
        if (array == null) return result;
        for (JsonElement element : array) {
            JsonObject item = element.getAsJsonObject();
            result.add(new Finding(
                string(item, "package"), string(item, "version"), string(item, "cve"),
                string(item, "severity"), bool(item, "exploited"), stringOrNull(item, "fixed_in"),
                string(item, "summary"), strings(item, "via"), string(item, "reachability"),
                strings(item, "reachability_evidence"), string(item, "reason")
            ));
        }
        return List.copyOf(result);
    }

    private static String quote(String value) { return new com.google.gson.Gson().toJson(value); }
    private static String string(JsonObject value, String key) { return value.has(key) && !value.get(key).isJsonNull() ? value.get(key).getAsString() : ""; }
    private static String stringOrNull(JsonObject value, String key) { return value.has(key) && !value.get(key).isJsonNull() ? value.get(key).getAsString() : null; }
    private static boolean bool(JsonObject value, String key) { return value.has(key) && value.get(key).getAsBoolean(); }
    private static List<String> strings(JsonObject value, String key) {
        if (!value.has(key) || !value.get(key).isJsonArray()) return List.of();
        List<String> result = new ArrayList<>();
        for (JsonElement element : value.getAsJsonArray(key)) result.add(element.getAsString());
        return List.copyOf(result);
    }
}

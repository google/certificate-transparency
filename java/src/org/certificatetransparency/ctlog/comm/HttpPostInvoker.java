package org.certificatetransparency.ctlog.comm;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.DefaultHttpClient;

import java.io.IOException;

/**
 * Simple delegator to HttpClient, so it can be mocked
 */
public class HttpPostInvoker {
  /**
   * Make an HTTP POST method call to the given URL with the provided JSON payload.
   * @param url URL for POST method
   * @param jsonPayload Serialized JSON payload.
   * @return Server's response body.
   */
  public String makePostRequest(String url, String jsonPayload) {
    HttpClient httpClient = new DefaultHttpClient();
    try {
      HttpPost post = new HttpPost(url);
      post.setEntity(new StringEntity(jsonPayload, "utf-8"));
      post.addHeader("Content-Type", "application/json; charset=utf-8");

      return httpClient.execute(post, new BasicResponseHandler());
    } catch (IOException e) {
      throw new LogCommunicationException("Error making POST request to " + url, e);
    } finally {
      httpClient.getConnectionManager().shutdown();
    }
  }
}

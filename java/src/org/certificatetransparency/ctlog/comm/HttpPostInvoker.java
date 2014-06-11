package org.certificatetransparency.ctlog.comm;

import java.io.IOException;
import java.util.List;

import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import com.sun.org.apache.xml.internal.utils.URI;

/**
 * Simple delegator to HttpClient, so it can be mocked
 */
// TODO(eranm) rename HttpPostInvoker to HttpInvoker.
public class HttpPostInvoker {
  /**
   * Make an HTTP POST method call to the given URL with the provided JSON payload.
   * @param url URL for POST method
   * @param jsonPayload Serialized JSON payload.
   * @return Server's response body.
   */
  public String makePostRequest(String url, String jsonPayload) {
    try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
      HttpPost post = new HttpPost(url);
      post.setEntity(new StringEntity(jsonPayload, "utf-8"));
      post.addHeader("Content-Type", "application/json; charset=utf-8");

      return httpClient.execute(post, new BasicResponseHandler());
    } catch (IOException e) {
      throw new LogCommunicationException("Error making POST request to " + url, e);
    }
  }
  
  /**
   * Makes an HTTP GET method call to the given URL with the provides parameters.
   * @param ctUrl URL for GET method.
   * @return Server's response body.
   */
  public String makeGetRequest(String url) {
    return makeGetRequest(url, null);
  }
  
  /**
   * Makes an HTTP GET method call to the given URL with the provides parameters.
   * @param ctUrl URL for GET method.
   * @param params query parameters.
   * @return Server's response body.
   */
  public String makeGetRequest(String url, List<NameValuePair> params) {
    try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
      URI path = new URI(url);
      if (params != null) {
        path.setQueryString(URLEncodedUtils.format(params, "utf-8"));
      }
      HttpGet get = new HttpGet(path.toString());
      get.addHeader("Content-Type", "application/json; charset=utf-8");

      return httpClient.execute(get, new BasicResponseHandler());
    } catch (IOException e) {
      throw new LogCommunicationException("Error making GET request to " + url, e);
    }
  }
}

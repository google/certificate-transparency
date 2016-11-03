package org.certificatetransparency.ctlog.comm;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;

import com.google.common.collect.ImmutableList;

/**
 * Simple delegator to HttpClient, so it can be mocked
 */
public class HttpInvoker {
  private static Log LOG = LogFactory.getLog(HttpInvoker.class);

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
   * @param url URL for GET method.
   * @return Server's response body.
   */
  public String makeGetRequest(String url) {
    return makeGetRequest(url, ImmutableList.<NameValuePair>of());
  }

  /**
   * Makes an HTTP GET method call to the given URL with the provides parameters.
   * @param url URL for GET method.
   * @param params query parameters.
   * @return Server's response body.
   */
  public String makeGetRequest(String url, List<NameValuePair> params) {
    try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
      HttpGet get = new HttpGet(new URIBuilder(url).addParameters(params).build());
      get.addHeader("Accept", "*/* charset=utf-8");
      get.addHeader("Content-Type", "text/plain; charset=utf-8");

      return httpClient.execute(get, new BasicResponseHandler());
    } catch (IOException | URISyntaxException e) {
      throw new LogCommunicationException("Error making GET request to " + url, e);
    }
  }

  /**
   * Execute a HTTP GET request to the given URL with the specified parameters and a
   * default retry. If the request fails, it will be retried.
   *
   * @param url URL for GET method.
   * @param params query parameters.
   *
   * @return the body of the response
   */
  public String executeGetRequestWithRetry(String url, List<NameValuePair> params) {
    return executeGetRequestWithRetry(url, params, 3);
  }

  /**
   * Execute a HTTP GET request to the given URL with the specified parameters and a
   * retry. If the request fails, it will be retried.
   *
   * @param url URL for GET method.
   * @param params query parameters.
   * @param maxRetries maximum number of retries.
   *
   * @return the body of the response
   */
  public String executeGetRequestWithRetry(String url, List<NameValuePair> params, int maxRetries) {
    for (int i = 0; i < maxRetries; i++) {
      try {
        return makeGetRequest(url, params);
      } catch (LogCommunicationException e) {
        if (i < 2) {
            LOG.info(String.format("Received exception on try %d. Retrying...", i), e);
            continue;
        }
        throw e;
      }
    }
    throw new LogCommunicationException("Failed to retrieve data", null);
  }
}

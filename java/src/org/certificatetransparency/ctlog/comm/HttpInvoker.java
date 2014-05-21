package org.certificatetransparency.ctlog.comm;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

/**
 * Simple delegator to HttpClient, so it can be mocked
 */
public class HttpInvoker {
  Log LOG = LogFactory.getLog(HttpInvoker.class);

  /**
   * Make an HTTP POST method call to the given URL with the provided JSON payload.
   *
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

  public String getData(String url, List<NameValuePair> params) {
    for (int i = 0; i < 3; i++) {
      try {
        return executeRequest(url, params);
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

  private String executeRequest(String url, List<NameValuePair> params) {
    try (CloseableHttpClient httpClient = HttpClientBuilder.create().build()) {
      HttpGet get = new HttpGet(new URIBuilder(url).addParameters(params).build());
      get.addHeader("Accept", "*/* charset=utf-8");
      get.addHeader("Content-Type", "text/plain; charset=utf-8");
      HttpEntity entity = httpClient.execute(get).getEntity();
      return EntityUtils.toString(entity, Charset.forName("UTF-8"));

    } catch (IOException | URISyntaxException e) {
      throw new LogCommunicationException("Error making GET request to " + url, e);
    }
  }
}

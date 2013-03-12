package org.scribe.builder.api;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.model.OAuthConfig;
import org.scribe.model.OAuthConstants;
import org.scribe.model.OAuthRequest;
import org.scribe.model.Response;
import org.scribe.model.Token;
import org.scribe.model.Verb;
import org.scribe.model.Verifier;
import org.scribe.oauth.OAuth20ServiceImpl;
import org.scribe.oauth.OAuthService;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

public class GoogleApi20 extends DefaultApi20 {
  private static final String AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=%s&redirect_uri=%s";
  private static final String SCOPE         = "&scope=%s";
  private static final String ACCESS_TYPE   = "&access_type=%s";

  @Override
  public String getAccessTokenEndpoint() {
    return "https://accounts.google.com/o/oauth2/token";
  }

  @Override
  public AccessTokenExtractor getAccessTokenExtractor() {
    return new AccessTokenExtractor() {

      public Token extract(String response) {
        Preconditions.checkEmptyString(response,
            "Response body is incorrect. Can't extract a token from an empty string");

        Matcher matcher = Pattern.compile("\"access_token\" : \"([^&\"]+)\"").matcher(response);
        Matcher refreshMatcher = Pattern.compile("\"refresh_token\" : \"([^&\"]+)\"").matcher(response);
        Matcher expiryMatcher = Pattern.compile("\"expires_in\" : ([0-9]+)").matcher(response);
        if (matcher.find()) {
          String token = OAuthEncoder.decode(matcher.group(1));
          Token refreshToken = null;
          int expiresIn = -1;

          if (refreshMatcher.find()) {
            String refreshTokenString = OAuthEncoder.decode(refreshMatcher.group(1));
            refreshToken = new Token(refreshTokenString, "", response);
          }
          
          if (expiryMatcher.find()) {
            String expiryString = OAuthEncoder.decode(expiryMatcher.group(1));
            expiresIn = Integer.parseInt(expiryString);
          }

          return new Token(token, "", response, refreshToken, expiresIn);
        } else {
          throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'",
              null);
        }
      }
    };
  }

  @Override
  public String getAuthorizationUrl(OAuthConfig config) {
    String url = String.format(AUTHORIZE_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()));
    if (config.hasScope()) {
      // Append scope if present
      url = url.concat(String.format(SCOPE, OAuthEncoder.encode(config.getScope())));
    }
    if (config.hasAccessType()) {
      // Append access type if present
      url = url.concat(String.format(ACCESS_TYPE, OAuthEncoder.encode(config.getAccessType())));
    }
    return url;

  }

  @Override
  public Verb getAccessTokenVerb() {
    return Verb.POST;
  }

  @Override
  public OAuthService createService(OAuthConfig config) {
    return new GoogleOAuth2Service(this, config);
  }

  private static class GoogleOAuth2Service extends OAuth20ServiceImpl {

    private static final String GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code";
    private static final String GRANT_TYPE                    = "grant_type";
    private DefaultApi20        api;
    private OAuthConfig         config;

    public GoogleOAuth2Service(DefaultApi20 api, OAuthConfig config) {
      super(api, config);
      this.api = api;
      this.config = config;
    }

    @Override
    public Token getAccessToken(Token requestToken, Verifier verifier) {
      OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), api.getAccessTokenEndpoint());
      switch (api.getAccessTokenVerb()) {
      case POST:
        request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
        request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
        request.addBodyParameter(OAuthConstants.CODE, verifier.getValue());
        request.addBodyParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
        request.addBodyParameter(GRANT_TYPE, GRANT_TYPE_AUTHORIZATION_CODE);
        break;
      case GET:
      default:
        request.addQuerystringParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
        request.addQuerystringParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
        request.addQuerystringParameter(OAuthConstants.CODE, verifier.getValue());
        request.addQuerystringParameter(OAuthConstants.REDIRECT_URI, config.getCallback());
        if (config.hasScope())
          request.addQuerystringParameter(OAuthConstants.SCOPE, config.getScope());
      }
      Response response = request.send();
      return api.getAccessTokenExtractor().extract(response.getBody());
    }

    @Override
    public Token refreshAccessToken(Token accessToken) {
      String accessTokenEndpoint = api.getAccessTokenEndpoint();
      OAuthRequest request = new OAuthRequest(api.getAccessTokenVerb(), accessTokenEndpoint);
      request.addBodyParameter(OAuthConstants.CLIENT_ID, config.getApiKey());
      request.addBodyParameter(OAuthConstants.CLIENT_SECRET, config.getApiSecret());
      request.addBodyParameter(OAuthConstants.GRANT_TYPE, api.getRefreshTokenParameterName());
      request.addBodyParameter(api.getRefreshTokenParameterName(), accessToken.getToken());
      Response response = request.send();
      return api.getAccessTokenExtractor().extract(response.getBody());
    }
  }

  @Override
  public String getRefreshTokenParameterName() {
    return "refresh_token";
  }

}

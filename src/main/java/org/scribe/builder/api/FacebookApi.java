package org.scribe.builder.api;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.TokenExtractor20Impl;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Token;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

public class FacebookApi extends DefaultApi20 {
  private static final String AUTHORIZE_URL        = "https://www.facebook.com/dialog/oauth?client_id=%s&redirect_uri=%s";
  private static final String SCOPED_AUTHORIZE_URL = AUTHORIZE_URL + "&scope=%s";

  private class FacebookTokenExtractor extends TokenExtractor20Impl {

    private static final String TOKEN_REGEX = "expires=([0-9]+)";

    @Override
    public Token extract(String response) {
      Token token = super.extract(response);

      Matcher matcher = Pattern.compile(TOKEN_REGEX).matcher(response);
      if (matcher.find()) {
        int expires = Integer.valueOf(OAuthEncoder.decode(matcher.group(1)));
        token.setExpiresIn(expires);
      }

      return token;
    }
  }

  @Override
  public String getAccessTokenEndpoint() {
    return "https://graph.facebook.com/oauth/access_token";
  }

  @Override
  public String getAuthorizationUrl(OAuthConfig config) {
    Preconditions.checkValidUrl(config.getCallback(),
        "Must provide a valid url as callback. Facebook does not support OOB");

    // Append scope if present
    if (config.hasScope()) {
      return String.format(SCOPED_AUTHORIZE_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()),
          OAuthEncoder.encode(config.getScope()));
    } else {
      return String.format(AUTHORIZE_URL, config.getApiKey(), OAuthEncoder.encode(config.getCallback()));
    }
  }

  @Override
  public AccessTokenExtractor getAccessTokenExtractor() {
    return new FacebookTokenExtractor();
  }

  @Override
  public String getRefreshTokenParameterName() {
    return "fb_exchange_token";
  }
}
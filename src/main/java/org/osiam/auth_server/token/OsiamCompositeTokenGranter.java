/*
 * Copyright (C) 2013 tarent AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.osiam.auth_server.token;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.osiam.resources.scim.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultExpiringOAuth2RefreshToken;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.provider.CompositeTokenGranter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;

/**
 * Custom TokenGranter, which add additional information to spring's accesstoken, which the resource server needed.
 * Iterate over all configured token granters and choose the one which needed for the current authentication process.
 * 
 */
public class OsiamCompositeTokenGranter extends CompositeTokenGranter {

    private AuthorizationCodeServices authorizationCodeServices;

    public OsiamCompositeTokenGranter(List<TokenGranter> tokenGranters, AuthorizationCodeServices authorizationCodeServices) {
        super(tokenGranters);
        this.authorizationCodeServices = authorizationCodeServices;
    }

    // TODO: AuthenticationRequest -> TokenRequest is correct?
    public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
        OAuth2AccessToken grant = super.grant(grantType, tokenRequest);
        if (grant != null) {
            DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) grant;
            Map<String, Object> additionalInformation = new HashMap<String, Object>();
            additionalInformation.put("access_token", token.getValue());
            additionalInformation.put("expires_at", token.getExpiration());

            StringBuilder scopes = new StringBuilder();
            for (String scopeString : token.getScope()) {
                scopes.append(scopeString).append(" ");
            }
            additionalInformation.put("scopes", scopes);

            if (token.getRefreshToken() != null) {
                DefaultExpiringOAuth2RefreshToken refreshToken = (DefaultExpiringOAuth2RefreshToken) token
                        .getRefreshToken();
                additionalInformation.put("refresh_token", refreshToken.getValue());
                additionalInformation.put("refresh_token_expires_at", refreshToken.getExpiration());
            }

            additionalInformation.put("token_type", token.getTokenType());
            additionalInformation.put("client_id", tokenRequest.getClientId());

            // TODO: running?
            OAuth2Authentication auth = getAuthorizationRequestHolder(tokenRequest.getRequestParameters());

            if (auth.getUserAuthentication() != null && auth.getPrincipal() instanceof User) {
                User user = (User) auth.getPrincipal();
                additionalInformation.put("user_name", user.getUserName());
                additionalInformation.put("user_id", user.getId());
            }

            token.setAdditionalInformation(additionalInformation);
        }
        return grant;
    }

    private OAuth2Authentication getAuthorizationRequestHolder(Map<String, String> parameters) {
        String authorizationCode = parameters.get("code");
        if (authorizationCode == null) {
            throw new OAuth2Exception("An authorization code must be supplied.");
        }

        OAuth2Authentication storedAuth = authorizationCodeServices.consumeAuthorizationCode(authorizationCode);
        if (storedAuth == null) {
            throw new InvalidGrantException("Invalid authorization code: " + authorizationCode);
        }
        return storedAuth;
    }
}

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

package org.osiam.auth_server.helper;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.common.exceptions.InvalidClientException;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.oauth2.common.exceptions.RedirectMismatchException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AbstractTokenGranter;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.stereotype.Service;

/**
 * This class is a fork of AuthorizationCodeTokenGranter the only difference is that we want to check if the pending
 * redirect uri startsWith the send redirect uri.
 * <p/>
 * The reason for this is that some connector do build different redirect uris when getting an authorization_code (like
 * Liferay) and send a simpler redirect uri when getting the access_token (because it doesn't matter on exchanging the
 * auth_code with an access_token)
 */
public class LessStrictRedirectUriAuthorizationCodeTokenGranter extends AbstractTokenGranter {

    private static final String GRANT_TYPE = "authorization_code";

    /*
     * Do not add a bean definition to spring xml. It will cause the problem, that two instances are used to serve the
     * "change auth_server code to access token" request. This will end up with a fault because the code is stored in one
     * instance and will be read from another where it does not exist.
     */
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;

    private OAuth2RequestFactory oAuth2RequestFactory;

    public LessStrictRedirectUriAuthorizationCodeTokenGranter(AuthorizationServerTokenServices tokenServices,
            ClientDetailsService clientDetailsService, OAuth2RequestFactory oAuth2RequestFactory) {
        super(tokenServices, clientDetailsService, oAuth2RequestFactory, GRANT_TYPE);
        this.oAuth2RequestFactory = oAuth2RequestFactory;
    }

    @Override
    protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {

        Map<String, String> parameters = tokenRequest.getRequestParameters();
        OAuth2Authentication storedAuth = getAuthorizationRequestHolder(parameters);
        // TODO: exist this parameter?
        String redirectUri = parameters.get("redirect_uri");

        OAuth2Request pendingAuthorizationRequest = storedAuth.getOAuth2Request();
        validateRedirectUri(redirectUri, pendingAuthorizationRequest);
        validateClientId(tokenRequest, pendingAuthorizationRequest);

        // Secret is not required in the authorization request, so it won't be available
        // in the pendingAuthorizationRequest. We do want to check that a secret is provided
        // in the token request, but that happens elsewhere.
        Map<String, String> combinedParameters = new HashMap<String, String>(storedAuth.getOAuth2Request()
                .getRequestParameters());
        // Combine the parameters adding the new ones last so they override if there are any clashes
        combinedParameters.putAll(parameters);
        // Similarly scopes are not required in the token request, so we don't make a comparison here, just
        // enforce validity through the AuthorizationRequestFactory.
        // TODO: is this working?
        OAuth2Request outgoingRequest = oAuth2RequestFactory.createOAuth2Request(oAuth2RequestFactory
                .createAuthorizationRequest(combinedParameters));

        Authentication userAuth = storedAuth.getUserAuthentication();
        return new OAuth2Authentication(outgoingRequest, userAuth);

    }

    private void validateClientId(TokenRequest authorizationRequest,
            OAuth2Request pendingAuthorizationRequest) {
        String pendingClientId = pendingAuthorizationRequest.getClientId();
        String clientId = authorizationRequest.getClientId();
        if (clientId != null && !clientId.equals(pendingClientId)) {
            // just a sanity check.
            throw new InvalidClientException("Client ID mismatch");
        }
    }

    private void validateRedirectUri(String redirectUri, OAuth2Request pendingAuthorizationRequest) {
        // https://jira.springsource.org/browse/SECOAUTH-333
        // This might be null, if the authorization was done without the redirect_uri parameter
        String redirectUriApprovalParameter = pendingAuthorizationRequest.getRequestParameters().get("redirect_uri");

        String uri = pendingAuthorizationRequest.getRedirectUri();

        if ((redirectUriApprovalParameter != null && redirectUri == null) ||
                (redirectUriApprovalParameter != null && (!uri.startsWith(redirectUri)))) {
            throw new RedirectMismatchException("Redirect URI mismatch.");
        }
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

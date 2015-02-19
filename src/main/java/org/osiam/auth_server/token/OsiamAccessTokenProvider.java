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

import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import org.osiam.auth_server.AuthServer;
import org.osiam.client.oauth.AccessToken;
import org.osiam.client.oauth.Scope;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

/**
 * TokenProvider which created an accesstoken for the auth_server server client
 * 
 */
@Service
public class OsiamAccessTokenProvider {

    @Autowired
    private TokenStore tokenStore;

    public AccessToken createAccessToken() {
        Set<String> scopes = new HashSet<String>();
        scopes.add(Scope.GET.toString());
        scopes.add(Scope.POST.toString());
        scopes.add(Scope.PATCH.toString());
        // Random scope, because the token services generates for every scope but same client
        // a different access token. This is only made due to the token expired problem, when the auth_server server
        // takes his actual access token, but the token is expired during the request to the resource server
        scopes.add(new Scope(UUID.randomUUID().toString()).toString());

        // TODO: need more param values
        OAuth2Request oAuth2Request = new OAuth2Request(null, AuthServer.AUTH_SERVER_CLIENT_ID, null, true, scopes,
                null, null, null, null);

        OAuth2Authentication oAuth2Authentication = new OAuth2Authentication(oAuth2Request, null);

        OAuth2AccessToken oAuth2AccessToken = new DefaultOAuth2AccessToken(UUID.randomUUID().toString());

        tokenStore.storeAccessToken(oAuth2AccessToken, oAuth2Authentication);

        return new AccessToken.Builder(oAuth2AccessToken.getValue()).build();
    }
}

package org.osiam.auth_server;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import javax.servlet.Filter;
import javax.sql.DataSource;

import org.osiam.auth_server.helper.LessStrictRedirectUriAuthorizationCodeTokenGranter;
import org.osiam.auth_server.login.oauth.OsiamResourceOwnerPasswordTokenGranter;
import org.osiam.auth_server.oauth_client.ClientEntity;
import org.osiam.auth_server.oauth_client.ClientRepository;
import org.osiam.auth_server.token.OsiamCompositeTokenGranter;
import org.osiam.client.oauth.GrantType;
import org.osiam.client.oauth.Scope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenGranter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.refresh.RefreshTokenGranter;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

@Configuration
@EnableWebMvc
@EnableWebMvcSecurity
@EnableAutoConfiguration
@EnableTransactionManagement
@ComponentScan
@RestController
public class AuthServer {

    public static final String AUTH_SERVER_CLIENT_ID = "auth-server";
    public static final String AUTH_SERVER_SECRET = UUID.randomUUID().toString();
    private static final Logger LOG = LoggerFactory.getLogger(AuthServer.class);

    public static void main(String[] args) {
        SpringApplication.run(AuthServer.class, args);
    }

    @RequestMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
    public ServiceInfo getServiceInfo() throws JsonProcessingException {
        String version = getClass().getPackage().getImplementationVersion();
        String name = getClass().getPackage().getImplementationTitle();
        if (Strings.isNullOrEmpty(version)) {
            version = "Version not found";
        }
        if (Strings.isNullOrEmpty(name)) {
            name = "Name not found";
        }
        return new ServiceInfo(name, version);
    }

    @Bean
    public Filter characterEncodingFilter() {
        CharacterEncodingFilter characterEncodingFilter = new CharacterEncodingFilter();
        characterEncodingFilter.setEncoding("UTF-8");
        characterEncodingFilter.setForceEncoding(true);
        return characterEncodingFilter;
    }

    @Bean
    @Primary
    public ObjectMapper objectMapper() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        return objectMapper;
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class OAuth2Config extends AuthorizationServerConfigurerAdapter {

        @Autowired
        private AuthenticationManager restAuthenticationManager;

        @Autowired
        private DataSource dataSource;

        @Value("${org.osiam.auth-server.home}")
        private String authServerHome;

        @Autowired
        private ClientRepository clientRepository;

        private OsiamCompositeTokenGranter tokenGranter;

        @Bean
        public OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {
            return new OAuth2AccessDeniedHandler();
        }

        @Bean
        public JdbcTokenStore tokenStore() {
            return new JdbcTokenStore(dataSource);
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {

            ClientCredentialsTokenGranter clientCredentialsTokenGranter = new ClientCredentialsTokenGranter(
                    endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                    endpoints.getOAuth2RequestFactory());
            OsiamResourceOwnerPasswordTokenGranter osiamResourceOwnerPasswordTokenGranter = new OsiamResourceOwnerPasswordTokenGranter(
                    restAuthenticationManager, endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                    endpoints.getOAuth2RequestFactory());
            RefreshTokenGranter refreshTokenGranter = new RefreshTokenGranter(endpoints.getTokenServices(),
                    endpoints.getClientDetailsService(), endpoints.getOAuth2RequestFactory());
            LessStrictRedirectUriAuthorizationCodeTokenGranter lessStrictRedirectUriAuthorizationCodeTokenGranter = new LessStrictRedirectUriAuthorizationCodeTokenGranter(
                    endpoints.getTokenServices(), endpoints.getClientDetailsService(),
                    endpoints.getOAuth2RequestFactory());

            List<TokenGranter> tokenGranters = Arrays.asList(new TokenGranter[] { clientCredentialsTokenGranter,
                    osiamResourceOwnerPasswordTokenGranter, refreshTokenGranter,
                    lessStrictRedirectUriAuthorizationCodeTokenGranter });
            tokenGranter = new OsiamCompositeTokenGranter(tokenGranters, endpoints.getAuthorizationCodeServices());

            endpoints.authenticationManager(restAuthenticationManager).tokenStore(tokenStore())
                    .tokenGranter(tokenGranter);
        }

        @Bean
        public TokenGranter tokenGranter() {
            return tokenGranter;
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

            ClientEntity clientEntity = clientRepository.findById(AUTH_SERVER_CLIENT_ID);
            if (clientEntity == null) {
                LOG.info("No auth server client found. The auth server client will be created.");
                int validity = 10;
                clientEntity = new ClientEntity();
                Set<String> scopes = new HashSet<String>();
                scopes.add(Scope.GET.toString());
                scopes.add(Scope.POST.toString());
                scopes.add(Scope.PATCH.toString());
                Set<String> grants = new HashSet<String>();
                grants.add(GrantType.CLIENT_CREDENTIALS.toString());
                clientEntity.setId(AUTH_SERVER_CLIENT_ID);
                clientEntity.setRefreshTokenValiditySeconds(validity);
                clientEntity.setAccessTokenValiditySeconds(validity);
                clientEntity.setRedirectUri(authServerHome);
                clientEntity.setScope(scopes);
                clientEntity.setImplicit(true);
                clientEntity.setValidityInSeconds(validity);
                clientEntity.setGrants(grants);
                clientEntity.setClientSecret(AUTH_SERVER_SECRET);
                clientRepository.save(clientEntity);
            }

            // TODO: better handle with internal jdbcclientservice?
            clients.jdbc(dataSource).withClient(AUTH_SERVER_CLIENT_ID)
                    .authorizedGrantTypes(GrantType.CLIENT_CREDENTIALS.name())
                    .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
                    .scopes("read", "write", "trust")
                    .resourceIds("sparklr")
                    .accessTokenValiditySeconds(60)
                    .redirectUris(authServerHome)
                    .secret(AUTH_SERVER_SECRET);
        }
    }
}

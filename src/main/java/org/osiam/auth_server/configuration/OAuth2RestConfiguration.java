package org.osiam.auth_server.configuration;

import java.util.Arrays;

import org.osiam.auth_server.authorization.DynamicHTTPMethodScopeEnhancer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.UnanimousBased;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.vote.ScopeVoter;

@Configuration
@Order(2)
public class OAuth2RestConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // TODO
    }

    @Bean(name = "restAuthenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Bean
    public OAuth2AuthenticationEntryPoint oauthAuthenticationEntryPoint() {
        OAuth2AuthenticationEntryPoint authenticationEntryPoint = new OAuth2AuthenticationEntryPoint();
        authenticationEntryPoint.setRealmName("oauth2-authorization-server");
        return authenticationEntryPoint;
    }

    @Bean
    public UnanimousBased accessDecisionManager() {
        DynamicHTTPMethodScopeEnhancer dynamicHTTPMethodScopeEnhancer = new DynamicHTTPMethodScopeEnhancer(
                new ScopeVoter());
        return new UnanimousBased(Arrays.asList(new AccessDecisionVoter[] { dynamicHTTPMethodScopeEnhancer }));
    }
}

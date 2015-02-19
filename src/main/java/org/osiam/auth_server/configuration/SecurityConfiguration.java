package org.osiam.auth_server.configuration;

import org.osiam.auth_server.helper.LoginDecisionFilter;
import org.osiam.auth_server.login.OsiamCachingAuthenticationFailureHandler;
import org.osiam.auth_server.login.internal.InternalAuthenticationProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.encoding.ShaPasswordEncoder;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
//@EnableGlobalMethodSecurity(prePostEnabled = true)
//@Order(1)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private SavedRequestAwareAuthenticationSuccessHandler successHandler;

    @Bean(name = "loginAuthenticationManager")
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // TODO
        http.authorizeRequests().antMatchers("/oauth/**").denyAll().anyRequest()
                .fullyAuthenticated()
                .and()
                .formLogin().loginPage("/login").permitAll()
                .and()
                // .logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                // .and()
                .exceptionHandling().accessDeniedPage("/login/error");

        http.anonymous().init(http);

        http.addFilterBefore(loginDecisionFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public OAuth2AccessDeniedHandler oauthAccessDeniedHandler() {
        return new OAuth2AccessDeniedHandler();
    }

    @Bean
    public ShaPasswordEncoder passwordEncoder() {
        ShaPasswordEncoder passwordEncoder = new ShaPasswordEncoder(512);
        passwordEncoder.setIterations(1000);
        return passwordEncoder;
    }

    @Autowired
    public void registerGlobalAuthentication(AuthenticationManagerBuilder auth,
            InternalAuthenticationProvider internalAuthenticationProvider) throws Exception {
        auth.authenticationProvider(internalAuthenticationProvider);
    }

    @Bean
    public SavedRequestAwareAuthenticationSuccessHandler successHandler() {
        SavedRequestAwareAuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setAlwaysUseDefaultTargetUrl(false);
        return successHandler;
    }

    @Bean
    public OsiamCachingAuthenticationFailureHandler failureHandler() throws Exception {
        return new OsiamCachingAuthenticationFailureHandler(loginDecisionFilter(), "/login/error");
    }

    @Bean
    public LoginUrlAuthenticationEntryPoint loginUrlAuthenticationEntryPoint() {
        return new LoginUrlAuthenticationEntryPoint("/login");
    }

    @Bean
    public LoginDecisionFilter loginDecisionFilter() throws Exception {
        LoginDecisionFilter loginDecisionFilter = new LoginDecisionFilter();
        loginDecisionFilter.setAuthenticationManager(authenticationManagerBean());
        loginDecisionFilter.setAuthenticationSuccessHandler(successHandler);
        return loginDecisionFilter;
    }
}

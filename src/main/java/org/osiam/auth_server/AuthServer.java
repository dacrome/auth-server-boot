package org.osiam.auth_server;

import java.util.UUID;

import javax.servlet.Filter;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.context.web.SpringBootServletInitializer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.annotation.PropertySources;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.servlet.configuration.EnableWebMvcSecurity;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.base.Strings;

@SpringBootApplication
@EnableWebMvc
@EnableWebMvcSecurity
@EnableTransactionManagement
@RestController
@EnableAspectJAutoProxy(proxyTargetClass = true)
@PropertySources({ @PropertySource(value = { "classpath:/auth-server.properties" }),
        @PropertySource(value = { "${osiam.auth.server.config.file:classpath:/auth-server.properties}" }) })
public class AuthServer extends SpringBootServletInitializer {

    public static final String AUTH_SERVER_CLIENT_ID = "auth-server";
    public static final String AUTH_SERVER_SECRET = UUID.randomUUID().toString();

    public static void main(String[] args) {
        SpringApplication.run(AuthServer.class, args);
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder application) {
        return application
                .showBanner(true)
                .sources(AuthServer.class);
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
}

package org.osiam.auth_server.configuration;

import org.osiam.auth_server.template.resolvers.OsiamWebContextTemplateResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;
import org.thymeleaf.spring4.SpringTemplateEngine;

@Configuration
public class WebApplicationConfiguration extends WebMvcConfigurerAdapter {

    @Autowired
    public OsiamWebContextTemplateResolver webTemplateResolver(SpringTemplateEngine templateEngine) {
        OsiamWebContextTemplateResolver webTemplateResolver = new OsiamWebContextTemplateResolver();
        webTemplateResolver.setPrefix("classpath:/templates/web/");
        webTemplateResolver.setSuffix(".html");
        webTemplateResolver.setTemplateMode("HTML5");
        webTemplateResolver.setCharacterEncoding("UTF-8");
        webTemplateResolver.setOrder(1);
        templateEngine.addTemplateResolver(webTemplateResolver);
        return webTemplateResolver;
    }

    @Bean
    public ResourceBundleMessageSource messageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setDefaultEncoding("UTF-8");
        messageSource.setBasename("i18n/login");
        return messageSource;
    }

    @Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        registry.addResourceHandler("/css/**").addResourceLocations("classpath:/resources/css/");
        registry.addResourceHandler("/js/**").addResourceLocations("classpath:/resources/js/");
    }
}
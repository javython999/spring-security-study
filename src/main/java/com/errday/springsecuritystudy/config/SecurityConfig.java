package com.errday.springsecuritystudy.config;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return webSecurity -> webSecurity.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http.authorizeHttpRequests(authorize -> authorize
               .anyRequest().access(authorizationManager(null)))
               .formLogin(Customizer.withDefaults())
               .csrf(AbstractHttpConfigurer::disable);
       return http.build();
    }

    @Bean
    public AuthorizationManager<RequestAuthorizationContext> authorizationManager(HandlerMappingIntrospector introspector) {
        List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = new ArrayList<>();

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry0 =
                new RequestMatcherEntry<>(new MvcRequestMatcher(introspector, "/user"), AuthorityAuthorizationManager.hasAuthority("ROLE_USER"));

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry1 =
                new RequestMatcherEntry<>(new MvcRequestMatcher(introspector, "/db"), AuthorityAuthorizationManager.hasAuthority("ROLE_DB"));

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry2 =
                new RequestMatcherEntry<>(new MvcRequestMatcher(introspector, "/admin"), AuthorityAuthorizationManager.hasRole("ADMIN"));

        RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> entry3 =
                new RequestMatcherEntry<>(AnyRequestMatcher.INSTANCE, AuthorityAuthorizationManager.hasRole("ADMIN"));

        mappings.add(entry0);
        mappings.add(entry1);
        mappings.add(entry2);
        mappings.add(entry3);

        return new CustomRequestMatcherDelegatingAuthorizationManager(mappings);
    }


}

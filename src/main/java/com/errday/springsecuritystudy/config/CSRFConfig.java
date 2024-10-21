package com.errday.springsecuritystudy.config;

import com.errday.springsecuritystudy.filter.CsrfCookieFilter;
import com.errday.springsecuritystudy.handler.SpaCsrfTokenRequestHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.XorCsrfTokenRequestAttributeHandler;

//@Configuration
//@EnableWebSecurity
public class CSRFConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        SpaCsrfTokenRequestHandler spaCsrfTokenRequestHandler = new SpaCsrfTokenRequestHandler();

        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/csrf", "/csrfToken", "/form", "/formCsrf" ,"/cookie", "/cookieCsrf").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(spaCsrfTokenRequestHandler)
                )
                .addFilterBefore(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
        ;
        return http.build();
    }

    /*@Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {


        CookieCsrfTokenRepository csrfTokenRepository = new CookieCsrfTokenRepository();
        XorCsrfTokenRequestAttributeHandler xorCsrfTokenRequestAttributeHandler = new XorCsrfTokenRequestAttributeHandler();
        xorCsrfTokenRequestAttributeHandler.setCsrfRequestAttributeName(null);


        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/csrf", "/csrfToken", "/form", "/formCsrf").permitAll()
                        .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                //.csrf(csrf -> csrf.ignoringRequestMatchers("/csrf/**"))
                *//*.csrf(csrf -> csrf
                        .csrfTokenRequestHandler(xorCsrfTokenRequestAttributeHandler)
                )*//*
                .csrf(Customizer.withDefaults())
        ;
        return http.build();
    }*/

}

package com.errday.springsecuritystudy.config;

import com.errday.springsecuritystudy.component.CustomRequestMatcher;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
//@EnableWebSecurity
public class SecurityMatcherConfig {


    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ApplicationContext context) throws Exception {

        http.authorizeHttpRequests(auth -> auth
                    .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
        ;

        return http.build();
    }

    @Bean
    @Order(1)
    SecurityFilterChain securityFilterChain2(HttpSecurity http, ApplicationContext context) throws Exception {

        http.securityMatchers(matchers -> matchers.requestMatchers("/api/**", "/oauth/**"))
            .authorizeHttpRequests(authorize -> authorize.anyRequest().permitAll())
        ;

        return http.build();
    }

}

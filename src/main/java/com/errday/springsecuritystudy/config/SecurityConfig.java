package com.errday.springsecuritystudy.config;

import com.errday.springsecuritystudy.CustomAuthenticationProvider;
import com.errday.springsecuritystudy.CustomAuthenticationProvider2;
import com.errday.springsecuritystudy.CustomAuthenticationSuccessEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ApplicationEventPublisher eventPublisher;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .anyRequest().authenticated())
            .formLogin(form -> form
                    .successHandler(
                            (request, response, authentication) -> {
                                eventPublisher.publishEvent(new CustomAuthenticationSuccessEvent(authentication));
                                response.sendRedirect("/");
                            }
                    )
            )
                .authenticationProvider(customAuthenticationProvider2())
            .csrf(AbstractHttpConfigurer::disable);
        return http.build();
    }

    @Bean
    public DefaultAuthenticationEventPublisher authenticationEventPublisher(ApplicationEventPublisher eventPublisher) {
        return new DefaultAuthenticationEventPublisher(eventPublisher);
    }

    @Bean
    public CustomAuthenticationProvider2 customAuthenticationProvider2() {
        return new CustomAuthenticationProvider2(authenticationEventPublisher(null));
    }
}

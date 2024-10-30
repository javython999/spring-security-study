package com.errday.springsecuritystudy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
            .authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/user").hasAuthority("ROLE_USER")
                    .requestMatchers("/db").hasAuthority("ROLE_DB")
                    .requestMatchers("/admin").hasAuthority("ROLE_ADMIN")
                    .anyRequest().permitAll())
//                .formLogin(Customizer.withDefaults())
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy(
                "ROLE_ADMIN > ROLE_DB\n"
                + "ROLE_DB > ROLE_MANAGER\n"
                + "ROLE_MANAGER > ROLE_USER\n"
                + "ROLE_USER > ROLE_ANONYMOUS\n"
        );
        return roleHierarchy;
    }
}

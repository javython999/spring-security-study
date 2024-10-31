package com.errday.springsecuritystudy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
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
    @Order(1) // @Order를 사용하여 어떤 SecurityFilterChain을 먼저 수행 할지 지정한다. 아래 설정보다 우선적으로 보안 기능을 수행한다.
    public SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/**")
                .authorizeHttpRequests(authorize -> authorize.anyRequest().hasRole("ADMIN"))
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean // @Order가 지정되지 않으면 마지막으로 간주 된다.
    public SecurityFilterChain formLoginFilter(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()) // HttpSecurity가 /api/** 를 제외한 모든 URL에 적용된다.
                .formLogin(Customizer.withDefaults());
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

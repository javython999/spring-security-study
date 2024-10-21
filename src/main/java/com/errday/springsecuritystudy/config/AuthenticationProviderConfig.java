package com.errday.springsecuritystudy.config;

import com.errday.springsecuritystudy.filter.CustomAuthenticationFilter;
import com.errday.springsecuritystudy.provider.CustomAuthenticationProvider;
import com.errday.springsecuritystudy.provider.CustomDaoAuthenticationProvider;
import com.errday.springsecuritystudy.provider.CustomDaoAuthenticationProvider2;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationProvider;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

//@Configuration
//@EnableWebSecurity
public class AuthenticationProviderConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        AuthenticationManagerBuilder builder = http.getSharedObject(AuthenticationManagerBuilder.class);
        builder.authenticationProvider(new CustomDaoAuthenticationProvider());
        builder.authenticationProvider(new CustomDaoAuthenticationProvider2());

        http.authorizeHttpRequests(auth -> auth
                    //.requestMatchers("/").permitAll()
                    .anyRequest().authenticated())
                .formLogin(Customizer.withDefaults());
                //.authenticationProvider(new CustomDaoAuthenticationProvider())
                //.authenticationProvider(new CustomDaoAuthenticationProvider());
        return http.build();
    }

}

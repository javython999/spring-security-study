package com.errday.springsecuritystudy.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

//@Configuration
@EnableWebSecurity
public class LogoutConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests(auth -> auth
                    .requestMatchers("/logoutSuccess").permitAll()
                    .anyRequest().authenticated()
                )
                .formLogin(Customizer.withDefaults())
                //.csrf(AbstractHttpConfigurer::disable)
                .logout(logout -> logout
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "POST"))
                    .logoutSuccessUrl("/logoutSuccess")
                    .logoutSuccessHandler((request, response, authentication) -> response.sendRedirect("/logoutSuccess"))
                    .deleteCookies("JSESSIONID", "remember-me")
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
                    .addLogoutHandler((request, response, authentication) -> {
                        request.getSession().invalidate();
                        SecurityContextHolder.getContextHolderStrategy().getContext().setAuthentication(null);
                        SecurityContextHolder.clearContext();
                    })
                    .permitAll()
                );
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}1111").roles("USER").build();
        return new InMemoryUserDetailsManager(user);
    }
}

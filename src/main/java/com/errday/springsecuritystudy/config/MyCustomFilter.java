package com.errday.springsecuritystudy.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.Setter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Setter
public class MyCustomFilter extends OncePerRequestFilter {

    private boolean flag;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        if (flag) {

            try {
                String username = request.getParameter("username");
                String password = request.getParameter("password");
                request.login(username, password);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
        }
        filterChain.doFilter(request, response);
    }
}

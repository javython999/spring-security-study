package com.errday.springsecuritystudy.component;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.web.util.matcher.RequestMatcher;

@RequiredArgsConstructor
public class CustomRequestMatcher implements RequestMatcher {

    private final String urlPattern;

    @Override
    public boolean matches(HttpServletRequest request) {
        String requestURI = request.getRequestURI();
        return requestURI.startsWith(urlPattern);
    }
}

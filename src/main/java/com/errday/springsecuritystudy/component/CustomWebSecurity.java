package com.errday.springsecuritystudy.component;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component("customWebSecurity")
public class CustomWebSecurity {

    public boolean check(Authentication authentication, HttpServletRequest request) {
        return !"anonymousUser".equals(authentication.getName()) && authentication.isAuthenticated();
    }
}

package com.errday.springsecuritystudy.config;

import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.core.Authentication;

public class CustomAuthenticationSuccessEvent extends AbstractAuthenticationEvent {
    public CustomAuthenticationSuccessEvent(Authentication authentication) {
        super(authentication);
    }
}
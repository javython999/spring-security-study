package com.errday.springsecuritystudy;

import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;

public class CustomAuthenticationSuccessEvent extends AuthenticationSuccessEvent {

    public CustomAuthenticationSuccessEvent(Authentication authentication) {
        super(authentication);
    }
}

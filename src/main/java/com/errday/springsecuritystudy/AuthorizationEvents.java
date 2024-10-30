package com.errday.springsecuritystudy;

import org.springframework.context.event.EventListener;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthorizationEvents {
    @EventListener
    public void onAuthorization(AuthorizationEvent event) {
        System.out.println("Authorization event received: " + event.getAuthentication().get().getAuthorities());
    }

    @EventListener
    public void onAuthorization(AuthorizationDeniedEvent failure) {
        System.out.println("Authorization denied: " + failure.getAuthentication().get().getAuthorities());
    }

    @EventListener
    public void onAuthorization(AuthorizationGrantedEvent success) {
        System.out.println("Authorization granted: " + success.getAuthentication().get().getAuthorities());
    }
}
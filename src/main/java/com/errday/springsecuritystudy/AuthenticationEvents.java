package com.errday.springsecuritystudy;

import com.errday.springsecuritystudy.config.CustomAuthenticationFailureEvent;
import com.errday.springsecuritystudy.config.CustomAuthenticationSuccessEvent;
import com.errday.springsecuritystudy.config.DefaultAuthenticationFailureEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.*;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onSuccess(InteractiveAuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onSuccess(CustomAuthenticationSuccessEvent success) {
        System.out.println("success = " + success.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AuthenticationFailureBadCredentialsEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(AuthenticationFailureProviderNotFoundEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(CustomAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }

    @EventListener
    public void onFailure(DefaultAuthenticationFailureEvent failures) {
        System.out.println("failures = " + failures.getException().getMessage());
    }
}

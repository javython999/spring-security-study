package com.errday.springsecuritystudy.controller;

import com.errday.springsecuritystudy.SecurityContextService;
import com.errday.springsecuritystudy.service.SessionInfoService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IndexController {

    private final SecurityContextService securityContextService;
    private final SessionInfoService sessionInfoService;

    @GetMapping("/index")
    public String index() {
        securityContextService.printAuthentication();
        return "index";
    }

    @GetMapping("/")
    public Authentication  root(Authentication authentication) {
        sessionInfoService.sessionInfo();
        return authentication;
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("anonymous")
    public String anonymous() {
        return "anonymous";
    }

    @GetMapping("/authentication")
    public String authentication(Authentication authentication) {
        if (authentication instanceof AnonymousAuthenticationToken) {
            return "anonymous";
        }
        return "not anonymous";
    }

    @GetMapping("/anonymousContext")
    public String anonymousContext(@CurrentSecurityContext SecurityContext securityContext) {
        return securityContext.getAuthentication().getName();
    }

    @GetMapping("/logoutSuccess")
    public String logoutSuccess() {
        return "logoutSuccess";
    }

    @GetMapping("/api/login")
    public String apiLogin() {
        return "apiLogin";
    }

    @GetMapping("/invalidSessionUrl")
    public String invalidSessionUrl() {
        return "invalidSessionUrl";
    }

    @GetMapping("/expiredUrl")
    public String expiredUrl() {
        return "expiredUrl";
    }

}

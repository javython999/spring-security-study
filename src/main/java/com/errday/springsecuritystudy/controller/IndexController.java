package com.errday.springsecuritystudy.controller;

import com.errday.springsecuritystudy.SecurityContextService;
import com.errday.springsecuritystudy.service.SessionInfoService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.CurrentSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IndexController {

    private final SecurityContextService securityContextService;
    //private final SessionInfoService sessionInfoService;

    @GetMapping("/index")
    public String index() {
        securityContextService.printAuthentication();
        return "index";
    }

    //@GetMapping("/")
    public Authentication  root(Authentication authentication) {
        //sessionInfoService.sessionInfo();
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

    @GetMapping("/login")
    public String login() {
        return "loginPage";
    }

    @GetMapping("/denied")
    public String denied() {
        return "denied";
    }

    @PostMapping("/csrf")
    public String csrf() {
        return "csrf 적용";
    }

    @GetMapping("/csrfToken")
    public String csrfToken(HttpServletRequest request) {
        CsrfToken csrfToken1 = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
        CsrfToken csrfToken2 = (CsrfToken) request.getAttribute("_csrf");

        String token = csrfToken1.getToken();

        return token;
    }

    @PostMapping("/formCsrf")
    public CsrfToken formCsrf(CsrfToken csrfToken) {
        return csrfToken;
    }

    @PostMapping("/cookieCsrf")
    public CsrfToken cookieCsrf(CsrfToken csrfToken) {
        return csrfToken;
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/myPage/points")
    public String myPage() {
        return "myPage";
    }

    @GetMapping("/manager")
    public String manager() {
        return "manager";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/admin/payment")
    public String adminPayment() {
        return "adminPayment";
    }

    @GetMapping("/resource/address_01")
    public String resourceAddress_01() {
        return "resourceAddress_01";
    }

    @GetMapping("/resource/address01")
    public String resourceAddress01() {
        return "resourceAddress01";
    }

    @PostMapping("/post")
    public String post() {
        return "post";
    }

}

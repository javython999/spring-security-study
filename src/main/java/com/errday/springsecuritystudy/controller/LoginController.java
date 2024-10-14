package com.errday.springsecuritystudy.controller;

import com.errday.springsecuritystudy.user.LoginRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class LoginController {

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository = new HttpSessionSecurityContextRepository();

    @PostMapping("/login")
    public Authentication login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        // 사용자 이름과 비밀번호를 담은 인증 객체를 생성한다.
        UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.getUsername(), loginRequest.getPassword());

        // 인증을 시도하고 최종 인증 결과를 반환한다.
        Authentication authentication = authenticationManager.authenticate(token);

        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().createEmptyContext();
        // 인증 결과를 컨텍스트에 저장한다.
        securityContext.setAuthentication(authentication);

        // 컨텍스트를 ThreadLocal에 저장한다.
        SecurityContextHolder.setContext(securityContext);

        // 컨텍스트를 세션에 저장해서 인증 상태를 영속한다.
        securityContextRepository.saveContext(securityContext, request, response);

        return authentication;
    }
}

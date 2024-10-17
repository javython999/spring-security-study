package com.errday.springsecuritystudy.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.stereotype.Service;

//@Service
@Slf4j
@RequiredArgsConstructor
public class SessionInfoService {

    private final SessionRegistry sessionRegistry;

    public void sessionInfo() {
        for (Object principal : sessionRegistry.getAllPrincipals()) {
            sessionRegistry.getAllSessions(principal, false).forEach(sessionInformation -> {
                log.info("사용자 = {} 세션ID = {} 최종 요청 시간 = {}", principal, sessionInformation.getSessionId(), sessionInformation.getLastRequest());
            });
        }

        System.out.println();
    }
}

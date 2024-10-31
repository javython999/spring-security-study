package com.errday.springsecuritystudy;

import org.springframework.scheduling.annotation.Async;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AsyncService {

    @Async
    public void ayncMethod() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();

        System.out.println("securityContext: " + securityContext);
        System.out.println("Parent Thread: " + Thread.currentThread().getName());
    }
}

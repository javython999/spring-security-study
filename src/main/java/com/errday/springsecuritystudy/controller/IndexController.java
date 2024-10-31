package com.errday.springsecuritystudy.controller;

import com.errday.springsecuritystudy.AsyncService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.Callable;

@RestController
@RequiredArgsConstructor
public class IndexController {

    private final AsyncService asyncService;

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/db")
    public String db() {
        return "db";
    }

    @GetMapping("/admin")
    public String admin() {
        return "admin";
    }

    @GetMapping("/callable")
    public Callable<Authentication> callable() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();

        System.out.println("securityContext: " + securityContext);
        System.out.println("Parent Thread: " + Thread.currentThread().getName());
        
        return new Callable<Authentication>() {
            @Override
            public Authentication call() throws Exception {
                SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();

                System.out.println("securityContext: " + securityContext);
                System.out.println("Parent Thread: " + Thread.currentThread().getName());

                return securityContext.getAuthentication();
            }
        };
    }

    @GetMapping("/async")
    public Authentication async() {
        SecurityContext securityContext = SecurityContextHolder.getContextHolderStrategy().getContext();

        System.out.println("securityContext: " + securityContext);
        System.out.println("Parent Thread: " + Thread.currentThread().getName());

        asyncService.ayncMethod();

        return securityContext.getAuthentication();
    }

}

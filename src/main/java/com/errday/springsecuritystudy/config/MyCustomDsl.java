package com.errday.springsecuritystudy.config;

import lombok.Setter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter;

@Setter
public class MyCustomDsl  extends AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> {

    private boolean flag;

    @Override
    public void init(HttpSecurity http) throws Exception {
        super.init(http);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        MyCustomFilter myCustomFilter = new MyCustomFilter();
        myCustomFilter.setFlag(flag);
        http.addFilterAfter(myCustomFilter, SecurityContextHolderAwareRequestFilter.class);
        super.configure(http);
    }

    public static MyCustomDsl customDsl() {
        return new MyCustomDsl();
    }

}

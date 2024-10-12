package com.errday.springsecuritystudy.service;

import com.errday.springsecuritystudy.user.AccountDto;
import com.errday.springsecuritystudy.user.CustomUserDetails;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.List;


public class CustomUserDetailsService implements UserDetailsService {

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        AccountDto accountDto = new AccountDto("user", "{noop}1111", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        return new CustomUserDetails(accountDto);
    }
}

package com.errday.springsecuritystudy.user;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class Account {
    private String owner;
    private boolean isSecure;
}

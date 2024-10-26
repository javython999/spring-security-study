package com.errday.springsecuritystudy.controller;

import com.errday.springsecuritystudy.service.DataService;
import com.errday.springsecuritystudy.user.Account;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class IndexController {

    private final DataService dataService;


    @GetMapping("/user")
    public String user() {
        return dataService.getUser();
    }

    @GetMapping("/owner")
    public Account owner(@RequestParam("name") String name) {
        return dataService.getOwner(name);
    }

    @GetMapping("/display")
    public String display() {
        return dataService.display();
    }
}

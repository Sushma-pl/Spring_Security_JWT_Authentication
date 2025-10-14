package com.JWTAuthentication.jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwtDemo {

    @GetMapping("/hello")
    public String printHello(){
        return "hello";
    }
}

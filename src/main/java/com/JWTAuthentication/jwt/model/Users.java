package com.JWTAuthentication.jwt.model;

import jakarta.persistence.Entity;

@Entity
public class Users {
    private String name;
    private String password;
    private String role;
}

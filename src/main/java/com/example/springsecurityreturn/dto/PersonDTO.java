package com.example.springsecurityreturn.dto;

import lombok.Getter;
import lombok.Setter;

import javax.persistence.Column;

@Getter
@Setter
public class PersonDTO {

    @Column(name = "username")
    private String username;

    @Column(name = "email")
    private String email;

    @Column(name = "year_of_birth")
    private int yearOfBirth;

    @Column(name = "password")
    private String password;

}

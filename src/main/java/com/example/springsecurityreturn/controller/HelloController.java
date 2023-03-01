package com.example.springsecurityreturn.controller;

import com.example.springsecurityreturn.security.PersonDetails;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@RequestMapping
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("show_user")
    @ResponseBody
    public String showUserInfo() {
        //достается объект который был проложен после успешной аутентификации
        //был положен в сессию, SpringSecurity положил его в контекст пользователя
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        PersonDetails personDetails = (PersonDetails) authentication.getPrincipal();
        //вывод данных пользователя
        System.out.println(personDetails.getPerson().toString());

        return personDetails.getUsername();
    }

}

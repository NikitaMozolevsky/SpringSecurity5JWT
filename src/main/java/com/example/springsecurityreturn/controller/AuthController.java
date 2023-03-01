package com.example.springsecurityreturn.controller;

import com.example.springsecurityreturn.dto.AuthenticationDTO;
import com.example.springsecurityreturn.dto.PersonDTO;
import com.example.springsecurityreturn.entity.Person;
import com.example.springsecurityreturn.security.JWTUtil;
import com.example.springsecurityreturn.services.PersonService;
import com.example.springsecurityreturn.util.PersonValidator;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final PersonValidator personValidator;
    private final PersonService personService;
    private final JWTUtil jwtUtil;
    private final ModelMapper modelMapper;
    private final AuthenticationManager authenticationManager;

    @Autowired
    public AuthController(PersonValidator personValidator, PersonService personService,
                          JWTUtil jwtUtil, ModelMapper modelMapper, AuthenticationManager authenticationManager) {
        this.personValidator = personValidator;
        this.personService = personService;
        this.jwtUtil = jwtUtil;
        this.modelMapper = modelMapper;
        this.authenticationManager = authenticationManager;
    }

    /*@GetMapping("/login")
    public String loginPage(@ModelAttribute(name = "user") Person person) {
        return "login";
    }

    @GetMapping("/registration")
    public String registrationPage(@ModelAttribute("person") Person person) {

        return "registration";
    }*/

    @PostMapping("/registration")
    //возвращает JSON Map
    public Map<String, String> performRegistration(/*@ModelAttribute("person")*/
            //т.к. теперь отправляется POST запрос на этот адрес в JSON с человеком
            @RequestBody @Valid PersonDTO personDTO,
                                      //an error is placed here
                                      BindingResult bindingResult) {
        //преобразование из DTO объекта в нормальный
        //DTO - оболочка, для использовании в представлении (view)
        Person person = convertToPerson(personDTO);
        personValidator.validate(person, bindingResult);

        if (bindingResult.hasErrors()) {
            return Map.of("message", "Ошибка"); //incorrect!
        }

        personService.register(person);

        //раньше работа была со SpringSecurity, session and cookies
        //now we generated token by username and send it to client as a JSON
        String token = jwtUtil.generateToken(person.getUsername());
        return Map.of("jwt-token", token);
    }

    //создание нового JWT токена с новым сроком годности
    @PostMapping("/login")
    public Map<String, String> performLogin(@RequestBody AuthenticationDTO authenticationDTO) {
        //UsernamePasswordAuthenticationToken
        //стандартный класс для инкапуляции логина и пароля в Spring Security
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                new UsernamePasswordAuthenticationToken(authenticationDTO.getUsername(),
                        authenticationDTO.getPassword());

        //validation login and pass
        try {
            authenticationManager.authenticate(usernamePasswordAuthenticationToken);
        } catch (BadCredentialsException e) {
            return Map.of("message", "Incorrect credentials");
        }

        String token = jwtUtil.generateToken(authenticationDTO.getUsername());
        return Map.of("jwt-token", token);
    }

    public Person convertToPerson(PersonDTO personDTO) {
        return modelMapper.map(personDTO, Person.class);
    }

}

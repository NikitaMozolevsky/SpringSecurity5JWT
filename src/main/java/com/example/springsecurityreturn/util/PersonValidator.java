package com.example.springsecurityreturn.util;

import com.example.springsecurityreturn.entity.Person;
import com.example.springsecurityreturn.security.PersonDetails;
import com.example.springsecurityreturn.services.PersonDetailsService;
import com.example.springsecurityreturn.services.PersonService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

@Component
public class PersonValidator implements Validator {

    private final PersonService personService;

    @Autowired
    public PersonValidator(PersonService personService) {
        this.personService = personService;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return Person.class.equals(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) { /**Check if this param is non-unique*/
        Person person = (Person) target;

        if (personService.personIsExist(person.getUsername())) {
            errors.rejectValue("username", //поля для которого добавляется ошибка
                    "", "Person with this name is already taken");
        }

        /**is there a person with the same name in the DB*/
    }
}

package com.example.springsecurityreturn.services;

import com.example.springsecurityreturn.entity.Person;
import com.example.springsecurityreturn.repository.PeopleRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class PersonService {

    private final PeopleRepository peopleRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public PersonService(PeopleRepository peopleRepository, PasswordEncoder passwordEncoder) {
        this.peopleRepository = peopleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public boolean personIsExist(String username) {
        return peopleRepository.findByUsername(username).isPresent();
    }

    @Transactional //the changes in DB is executing
    public void register(Person person) {

        //encoding
        person.setRole("ROLE_USER");
        person.setPassword(passwordEncoder.encode( person.getPassword()));
        peopleRepository.save(person);
    }
}

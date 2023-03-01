package com.example.springsecurityreturn.config;

import com.example.springsecurityreturn.services.PersonDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity //указывает на то, что конфигурационный класс SpringSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private static final String[] allowedPages = new String[] {
            "/auth/login",
            "/error",
            "/auth/registration",
            "/css/**"
    };

    private final PersonDetailsService personDetailsService;
    private final JWTFilter jwtFilter;

    @Autowired
    public SecurityConfig(PersonDetailsService personDetailsService, JWTFilter jwtFilter) {
        this.personDetailsService = personDetailsService;
        this.jwtFilter = jwtFilter;
    }

    //настройка формы для логина
    @Override //переопределяется из WebSecurityConfigurerAdapter
    protected void configure(HttpSecurity http) throws Exception {
        //конфигурация страницы входа, выхода, ошибки и т.д.
        //конфигурация авторизации (доступ по роли к страницам)
        //работает с http
        http
                //попытка отправки злоумышленииком формы, для каких-то злоумышленных
                //дел, доджится токеном на каждой thymeleaf странице
                //отключение защиты от межсайтовой подделки запросов
                //ненужен если не предполагается работа в браузере
                //т.к. исключены cross site requests forgery
                .csrf().disable()
                .authorizeHttpRequests()
                //страницы доступные всем
                .antMatchers(allowedPages).permitAll()
                //остальные запросы недоступны
                .anyRequest().authenticated()
                .and() //and - объединитель разных настроек, настройка авторизации
                .formLogin()
                .loginPage("/auth/login") //метод захода в систему\
                //SpringSecurity ожидает что сюда придут логин и пароль
                //SpringSecurity сам обрабатывает данные
                .loginProcessingUrl("/process_login")
                //что происходит при успешной аутентификации
                //перенаправление на /hello, true - всегда
                .defaultSuccessUrl("/hello", true)
                //unsuccessful with key error (located in view (th) show message)
                .failureForwardUrl("/auth/login?error")
                .and()
                //удаление пользователя из сессии, удаление кукиз у пользователя
                .logout().logoutUrl("/logout")
                //redirect to this page after logout
                .logoutSuccessUrl("/auth/login")
                .and()
                //не сохранять сессию на сервере (stateless)
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);//была ALWAYS

        //добавление фильтра в цепочку фильтров SpringSecurity
        //помогает производить аутентификацию
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);

    }

    //настраивает логику аутентификации
    //даем понять SpringSecurity что для аутентификации используется
    //именно этот AuthProviderImpl
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(personDetailsService)//упрощение, есть другая версия
                //прогоняет пароль через BCryptPasswordEncoder
                //при аутентификации
                .passwordEncoder(getPasswordEncoder());
    }

    @Bean //возвращается используемый алгоритм шифрования
    public PasswordEncoder getPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManager() {
        try {
            return super.authenticationManagerBean();
        } catch (Exception e) {
            throw new RuntimeException("AuthenticationManagerBean");
        }
    }

}

package com.hackerrank.springsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("john_doe")
                .password("{noop}student_password")
                .authorities("ROLE_STUDENT_USER")
                .and()
                .withUser("jane_doe")
                .password("{noop}admin_password")
                .authorities("ROLE_OFFICE_ADMIN");
    }
}

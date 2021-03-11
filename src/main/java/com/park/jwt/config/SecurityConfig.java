package com.park.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.park.jwt.config.jwt.JwtLoginFilter;

@EnableWebSecurity // 시큐리티 사용.
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	// Authentication 객체를 Bean으로 등록한다.
	// 이미 등록되어 있을 수 도 있다.
	
	// Baerer Auth 방식.
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		System.out.println("시큐리티 필터 실행됨.");
		http
			.addFilter(new JwtLoginFilter(authenticationManager()))
			//.addFilter(null)
			// csrf토큰을 사용하지 않는다.
			.csrf().disable()
			// form로그인 방식은 않쓴다.
			.formLogin().disable()
			// 헤더를 사용하지 않는다.
			.httpBasic().disable()
			// jwt방식을 사용할려면 stateless라는 것을 알려줘야한다.
			.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			.and()
			.authorizeRequests()
			.antMatchers("/user/**").access("hasRole('ROLE_USER')")
			.antMatchers("/admin/**").access("hasRole('ROLE_ADMIN')")
			.anyRequest().permitAll();
	}
}

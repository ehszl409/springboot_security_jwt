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
import com.park.jwt.config.jwt.JwtVerifyFilter;
import com.park.jwt.domain.UserRepo;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@EnableWebSecurity // 시큐리티 사용.
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final UserRepo userRepo;

	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	// Authentication 객체를 Bean으로 등록한다.
	// 이미 등록되어 있을 수 도 있다.
	
	// Baerer Auth 방식.
	// = 
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		System.out.println("시큐리티 필터 실행됨.");
		http
			// /login일떄만 동작하는 필터. (오직 POST요청일떄만 필터를 탄다.)
			.addFilter(new JwtLoginFilter(authenticationManager()))
			// 권한이 필요한 모든 요청에 동작한다.
			// 권한이나 인증이 필요할때 계속해서 동작한다.
			// 이 필터는 GET요청일시 무조건 탄다.
			.addFilter(new JwtVerifyFilter(authenticationManager(), userRepo))
			// csrf토큰을 사용하지 않는다.
			.csrf().disable()
			// form로그인 방식은 안쓴다.
			.formLogin().disable()
			// JSession을 쿠키에 저장해서 로그인을 하는 방식을 사용하지 않고
			// 오직 헤더를 통해서만 인증을 한다. 
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

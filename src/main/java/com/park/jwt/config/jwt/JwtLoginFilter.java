package com.park.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.park.jwt.web.dto.LoginReqDto;

import lombok.RequiredArgsConstructor;

// 응답해주기위해 토큰 만들어 주기. (시큐리티 필요없어짐.) 토큰은 헤더에 담긴다.
// UsernamePasswordAuthenticationToken으로 매니저가 로그인을 시도한다.
// 이 필터의 목적은 UsernamePasswordAuthenticationFilter 를 바꿔치기 한다.
// 기존의 x-www 방식으로 데이터를 받아오는것을 바꿔기하는것.
@RequiredArgsConstructor
public class JwtLoginFilter extends UsernamePasswordAuthenticationFilter{
	
	private final AuthenticationManager authenticationManager;
	
	// POST요청으로 /login요청이 들어오면 동작한다.
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("로그인 요청 옴.");
		
		ObjectMapper om = new ObjectMapper();
		LoginReqDto loginReqDto = null;
		
		try {
			// 파싱하는 코드.
			loginReqDto = om.readValue(request.getInputStream(), LoginReqDto.class);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// 1. UsernamePassword토큰 만들기
		System.out.println("토큰 만들기 시작.");
		UsernamePasswordAuthenticationToken authToken =
				new UsernamePasswordAuthenticationToken(loginReqDto.getUsername(), loginReqDto.getPassword());
		System.out.println("토큰 만들기 완료. : " + authToken);
		
		// 2. AuthenticationManager에게 토큰을 전달하면 자동으로 UserDetailsService가 호출
		// 		응답은 Authentication 으로 받는다. 그것을 리턴하면 끝.
		System.out.println("토큰 전달하기 시작.");
		authenticationManager.authenticate(authToken);
		System.out.println("토큰 전달하기 성공. : " + authenticationManager.authenticate(authToken));
		//System.out.println("authentication : " + authentication);
		return null;
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		System.out.println("로그인에 성공했습니다.");
	}
	
	@Override
	protected AuthenticationFailureHandler getFailureHandler() {
		// TODO Auto-generated method stub
		return super.getFailureHandler();
	}
}

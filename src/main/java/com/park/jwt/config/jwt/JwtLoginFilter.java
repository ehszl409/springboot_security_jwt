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

// 목적 : JWT토큰을 만들고 헤더에 담아서 응답 해준다. (그러면 인증과 관련된 시큐리티 기능을 필요 없어진다.)
// 방법 : UsernamePasswordAuthenticationFilter을 내가 만든 커스텀 필터로 바꿔치기 한다.
//			= 기존의 x-www 방식으로 데이터를 받아오는것을 Json 방식으로 바꿀 수 있다.
// 이유 : UsernamePasswordAuthenticationFilter는 UsernamePasswordAuthenticationToken을 만드는데
// 			AuthenticationManager가 UsernamePasswordAuthenticationToken을 통해
//			로그인을 진행한다. 로그인이 완료되면 Authentication 객체가 만들어지고
//			시큐리티의 권한관리 기능을 사용할 수 있게 된다. (인증은 JWT로 할 것이기에 인증기능은 사용하지 않는다.) 

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
			// 로그인시 들어오는 값을 받음. 키 벨류 방식
			loginReqDto = om.readValue(request.getInputStream(), LoginReqDto.class);
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("loginReqDto : " + loginReqDto);
		
		// 시큐리티가 알아서 해준것을 우리가 직접 만들어주는 방법
		// 1. UsernamePassword토큰 만들기
		System.out.println("auth 토큰 만들기 시작.");
		UsernamePasswordAuthenticationToken authToken =
				new UsernamePasswordAuthenticationToken(loginReqDto.getUsername(), loginReqDto.getPassword());
		System.out.println("auth 토큰 만들기 완료. : " + authToken);
		
		// 2. AuthenticationManager에게 토큰을 전달하면 자동으로 UserDetailsService가 호출
		// 		응답은 Authentication 으로 받는다. 그것을 리턴하면 끝.
		System.out.println("auth 토큰 전달하기 시작.");
		
		// authenticate가 실행되면 UserDetailsService의 loadUserByUsername함수를 자동으로 호출하게 된다.
		Authentication authentication = authenticationManager.authenticate(authToken);
		System.out.println("auth 토큰 전달하기 성공. : " + authentication);
		
		// 결론적으로 리턴해주면 세션을 만들어 준것. (JWT 토큰을 만든것이 아님.)
		return authentication;
	}
	
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		super.successfulAuthentication(request, response, chain, authResult);
		System.out.println("로그인 완료되어서 세션 만들어짐. 이제 JWT 토큰 만들어서 response.header에 응답할 차례");
	}
	
}

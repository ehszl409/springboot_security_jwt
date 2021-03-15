package com.park.jwt.config.jwt;

import java.io.IOException;

import javax.jws.soap.SOAPBinding.Use;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.park.jwt.config.auth.PrincipalDetails;
import com.park.jwt.domain.User;
import com.park.jwt.domain.UserRepo;

// 이 클래스의 목적. 만들어진  JWT토큰을 사용해서 로그인시 검증을 한다.
public class JwtVerifyFilter extends BasicAuthenticationFilter {
	
	private final AuthenticationManager authenticationManager;
	private final UserRepo userRepo;

	public JwtVerifyFilter(AuthenticationManager authenticationManager, UserRepo userRepo) {
		super(authenticationManager);
		
		this.authenticationManager = authenticationManager;
		this.userRepo = userRepo;
		
		
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		// TODO Auto-generated method stub
		String header = request.getHeader("Authorization");
		System.out.println("Authorization header : " + header);
		
		if(header == null || header.startsWith("Bearer ")) {
			// JWT 토큰이 없으면 여기 필터를 못타게하고 다른 필터를 타라고 내보낸다.
			System.out.println("JWT토큰이 없습니다.");
			chain.doFilter(request, response);
			return;
		}
		
		// 헤더 내용을 모두 날려버리고 순수한 토큰 값만 추출한다.
		String token = request.getHeader("Authorization").replace("Bearer ", "");
		
		// 검증1 : (헤더+페이로드+시크릿을 해쉬한 값)
		// 검증2 : (만료시간 확인)
		DecodedJWT dJwt = JWT.require(Algorithm.HMAC512("홍길동")).build().verify(token);
		Long userId = dJwt.getClaim("userId").asLong();
		
		// 영속화.
		User userEntity = userRepo.findById(userId).get();
		PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
		
		Authentication authentication = 
				new UsernamePasswordAuthenticationToken(principalDetails.getUsername(), 
						principalDetails.getPassword(),
						principalDetails.getAuthorities());
				SecurityContextHolder.getContext().setAuthentication(authentication);
		
		System.out.println("userId : " + userId);
		
		
		
		
		System.out.println("권한이나 인증이 필요한 요청이 들어옴.");
		chain.doFilter(request, response);
	}

}

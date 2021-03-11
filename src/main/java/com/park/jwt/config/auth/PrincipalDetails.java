package com.park.jwt.config.auth;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.park.jwt.domain.User;

import lombok.Data;

// UserDetails 타입으로 만들어 줘야한다.
// 시큐리티는 UserDetails만 호출할 뿐 우리가만든 객체를 호출하지 않는다.
@Data
public class PrincipalDetails implements UserDetails {
	private User user;

	
	// 시큐리티의 UserDetails에 필수적인 정보를 넘겨줘야한다.
	// 그래야지 시큐리티에서 UserDetails로 로그인과 회원가입을 관리해준다.
	public PrincipalDetails(User user) {
		System.out.println("UserDetails 실행됨.");
		this.user = user;
	}

	@Override
	public String getPassword() {
		System.out.println("UserDetails에 패스워드가 설정됨.");
		return user.getPassword();
	}

	@Override
	public String getUsername() {
		System.out.println("UserDetails에 유저네임이 설정됨.");
		return user.getUsername();
	}

	// 계정의 만료 여부
	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	// 계정 잠김 관련 
	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	// 비밀번호 만료
	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	// 계정 활성화
	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}
	
	// 사용자가 가지고 있는 권한은 무엇인지에 대해 시큐리티한테 알려줘야한다.
	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		// 권한을 넘겨주는 것이 목적이다.
				Collection<GrantedAuthority> collectors = new ArrayList<>();
				collectors.add(() -> "ROLE_" + user.getRoles().toString());
				return collectors;
	}
	
	

}

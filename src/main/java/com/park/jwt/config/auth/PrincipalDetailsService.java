package com.park.jwt.config.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.park.jwt.domain.User;
import com.park.jwt.domain.UserRepo;

import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
// 같은 타입이 두번 호출되면 나중에 호출된 타입이 덮어씌워진다.
public class PrincipalDetailsService implements UserDetailsService{
	
	private final UserRepo userRepo;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		System.out.println("loadUserByUsername 실행됨.");
		
		// 영속화
		User userEntity = userRepo.findByUsername(username);
		if(userEntity == null) {
			return null;
		} else {
			return new PrincipalDetails(userEntity);
		}
	}
}

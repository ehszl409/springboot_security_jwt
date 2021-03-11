package com.park.jwt.web;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.park.jwt.domain.User;
import com.park.jwt.domain.UserRepo;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@RestController
public class RestApiController {
	
	private final UserRepo userRepo;
	private final BCryptPasswordEncoder bCryptPasswordEncoder;

	@GetMapping({"","/"})
	public String home() {
		return "hello";
	}
	
	@GetMapping("/user")
	public String user() {
		return "user";
	}
	
	@GetMapping("/admin")
	public String admin() {
		return "admin";
	}
	
	@PostMapping("/join")
	public User join(@RequestBody User user) {
		String rawPassword = user.getPassword();
		String encPassword = bCryptPasswordEncoder.encode(rawPassword);
		
		user.setRoles("USER");
		user.setPassword(encPassword);
		return userRepo.save(user);
	}
}

package com.park.jwt.domain;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long>{
	public User findByUsername(String username);
}

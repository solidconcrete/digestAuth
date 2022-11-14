package com.security.digestAuth.repository;

import com.security.digestAuth.model.DigestUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;

public interface DigestUserRepo extends JpaRepository<DigestUser, Long>, JpaSpecificationExecutor<DigestUser> {
	DigestUser findByUsername(String username);
}

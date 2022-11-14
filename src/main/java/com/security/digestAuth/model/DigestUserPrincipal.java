package com.security.digestAuth.model;

import java.util.Collection;
import java.util.Collections;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public class DigestUserPrincipal implements UserDetails {
	private final DigestUser digestUser;

	public DigestUserPrincipal(DigestUser digestUser) {
		this.digestUser = digestUser;
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return Collections.singleton(new SimpleGrantedAuthority(digestUser.getAuthority()));
	}

	@Override
	public String getPassword() {
		return digestUser.getPassword();
	}

	@Override
	public String getUsername() {
		return digestUser.getUsername();
	}

	@Override
	public boolean isAccountNonExpired() {
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		return true;
	}

	@Override
	public boolean isEnabled() {
		return true;
	}
}

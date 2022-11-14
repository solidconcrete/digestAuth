package com.security.digestAuth.model;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Table;

import lombok.Data;
import lombok.ToString;

@Entity
@Data
@ToString
@Table(name = "DIGEST_USER")
public class DigestUser {

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	private long id;

	private String username;
	private String password;
	private String passResetCode;
	private String authority;

	public DigestUser() {

	}

	public DigestUser(String username, String password) {
		this.username = username;
		this.password = password;
	}
}

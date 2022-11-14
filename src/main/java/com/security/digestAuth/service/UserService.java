package com.security.digestAuth.service;

import java.util.Random;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import com.security.digestAuth.model.DigestUser;
import com.security.digestAuth.model.DigestUserPrincipal;
import com.security.digestAuth.repository.DigestUserRepo;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

	private final DigestUserRepo userRepo;

	private final JSONParser parser = new JSONParser();

	public void deleteUser() {
		// getLoggedInUser();
		userRepo.delete(getLoggedInUser());
	}

	public void registerAccount(String jsonCredentials) {
		DigestUser newUser = getCredentialsFromJson(jsonCredentials);
		DigestUser digestUser = userRepo.findByUsername(newUser.getUsername());
		if (digestUser != null) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "this username is already taken!");
		}
		newUser.setPassResetCode(generateRecoveryCode());
		newUser.setAuthority("USER");
		userRepo.save(newUser);
	}

	public void changePassword(String password) {
		DigestUser userToUpdate = getLoggedInUser();
		String newPassword;
		try {
			JSONObject object = (JSONObject) parser.parse(password);
			newPassword = object.get("password").toString();
		} catch (ParseException exception) {
			throw new RuntimeException();
		}
		userToUpdate.setPassword(newPassword);
		userRepo.save(userToUpdate);
	}

	public String getResetCode() {
		DigestUser user = getLoggedInUser();
		return user.getPassResetCode();
	}

	public void resetPassword(String body) {
		DigestUser userToUpdate = getLoggedInUser();
		String resetCode;
		String newPassword;
		try {
			JSONObject object = (JSONObject) parser.parse(body);
			newPassword = object.get("new-password").toString();
			resetCode = object.get("reset-code").toString();
		} catch (ParseException exception) {
			throw new RuntimeException();
		}
		if (!resetCode.equals(userToUpdate.getPassResetCode())) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Wrong password reset code!");
		}
		userToUpdate.setPassword(newPassword);
		userToUpdate.setPassResetCode(generateRecoveryCode());
		userRepo.save(userToUpdate);
	}

	//~~~~~~~~~~~~~~~~~~ADMIN STUFF~~~~~~~~~~~~~~~~~~~~~
	public String getAllUsers() {
		return userRepo.findAll().toString();
	}

	public void changePasswordAdmin(String body) {
		String userName;
		String newPassword;
		try {
			JSONObject object = (JSONObject) parser.parse(body);
			userName = object.get("username").toString();
			newPassword = object.get("new-password").toString();
		} catch (ParseException exception) {
			throw new RuntimeException();
		}
		DigestUser userToUpdate = userRepo.findByUsername(userName);
		userToUpdate.setPassword(newPassword);
		userRepo.save(userToUpdate);
	}

	public void adminDeleteUser(String username) {
		DigestUser userToDelete = userRepo.findByUsername(username);
		userRepo.delete(userToDelete);
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		DigestUser digestUser = userRepo.findByUsername(username);
		return new DigestUserPrincipal(digestUser);
	}

	private DigestUser getLoggedInUser() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return userRepo.findByUsername(authentication.getName());
	}

	private DigestUser getCredentialsFromJson(String jsonCredentials) {
		JSONParser parser = new JSONParser();
		try {
			JSONObject object = (JSONObject) parser.parse(jsonCredentials);
			return new DigestUser(object.get("username").toString(), object.get("password").toString());
		} catch (ParseException e) {
			throw new RuntimeException(e);
		}
	}

	private String generateRecoveryCode() {
		int leftLimit = 48; // numeral '0'
		int rightLimit = 122; // letter 'z'
		int targetStringLength = 10;
		Random random = new Random();

		return random.ints(leftLimit, rightLimit + 1)
				.filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
				.limit(targetStringLength)
				.collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
				.toString();
	}
}

package com.security.digestAuth.Controller;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.security.digestAuth.model.DigestUser;
import com.security.digestAuth.service.UserService;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class Controller {

	private final UserService userService;

	@RequestMapping(value = "/home")
	public String home() {
		DigestUser digestUser = new DigestUser();
		digestUser.setUsername("user");
		digestUser.setPassword("pass");
		return "Hello, authenticated User!";
	}

	@GetMapping(value = "get-reset-code")
	public String getResetCode() {
		return userService.getResetCode();
	}

	@PostMapping(value = "/register-account")
	public void registerAccount(@RequestBody String body) {
		userService.registerAccount(body);
	}

	@PostMapping(value = "/change-password")
	public void changePassword(@RequestBody String body) {
		userService.changePassword(body);
	}

	@PostMapping(value = "/reset-password")
	public void resetPassword(@RequestBody String body) {
		userService.resetPassword(body);
	}

	@DeleteMapping(value = "/remove-account")
	public void deleteUser() {
		userService.deleteUser();
	}

	@GetMapping(value = "/admin/users")
	public String getAllUsers() {
		return userService.getAllUsers();
	}

	@PostMapping(value = "/admin/change-password")
	public void changePasswordAdmin(@RequestBody String body) {
		userService.changePasswordAdmin(body);
	}

	@GetMapping (value = "/admin/remove-account/{username}")
	public void adminDeleteUser(@PathVariable("username") String username) {
		userService.adminDeleteUser(username);
	}

}

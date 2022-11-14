package com.security.digestAuth.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.authentication.www.DigestAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.DigestAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	@Autowired
	UserDetailsService userDetailsService;

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new PasswordEncoder() {
			@Override
			public String encode(CharSequence rawPassword) {
				return rawPassword.toString();
			}

			@Override
			public boolean matches(CharSequence rawPassword, String encodedPassword) {
				return rawPassword.toString().equals(encodedPassword);
			}
		};
	}

	@Bean
	public DigestAuthenticationEntryPoint digestEntryPoint() {
		DigestAuthenticationEntryPoint entryPoint = new DigestAuthenticationEntryPoint();
		entryPoint.setRealmName("Sparta");
		entryPoint.setKey("uniqueAndSecret");
		entryPoint.setNonceValiditySeconds(3600);
		return entryPoint;
	}

	@Bean
	public DigestAuthenticationFilter digestFilter() throws Exception {
		DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setAuthenticationEntryPoint(digestEntryPoint());
		filter.setUserDetailsService(userDetailsServiceBean());
		return filter;
	}

	@Override
	@Bean
	public UserDetailsService userDetailsServiceBean() throws Exception{
		return super.userDetailsServiceBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// http.exceptionHandling()
		// 		.authenticationEntryPoint(digestEntryPoint())
		// 		.and()
		// 		.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		// 		.and()
		// 		.authorizeRequests()
		// 		// .and()
		// 		.antMatchers("h2/**").permitAll()
		//
		// 		.antMatchers("/register-account/").permitAll()
		// 		.anyRequest().fullyAuthenticated()
		// 		.and()
		// 		.addFilterAfter(digestFilter(), BasicAuthenticationFilter.class)
		// 		.csrf().disable();

		http.exceptionHandling()
				.authenticationEntryPoint(digestEntryPoint())
				.and()
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
				.authorizeRequests()
				.antMatchers("/h2/**").permitAll()
				.antMatchers("/register-account").permitAll()
				.antMatchers("/admin/**").hasAuthority("ADMIN")
				.anyRequest().fullyAuthenticated()
				.and()
				.addFilterAfter(digestFilter(), BasicAuthenticationFilter.class)
				.csrf().disable();

	}

	@Override
	@Bean
	protected AuthenticationManager authenticationManager() throws Exception {
		return super.authenticationManager();
	}

	private CsrfTokenRepository csrfTokenRepository() {
		HttpSessionCsrfTokenRepository repository = new HttpSessionCsrfTokenRepository();
		repository.setSessionAttributeName("_csrf");
		return repository;
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth
			// .inMemoryAuthentication()
			// .withUser(username).password("pass").roles(role);
			.userDetailsService(userDetailsService);
	}
}

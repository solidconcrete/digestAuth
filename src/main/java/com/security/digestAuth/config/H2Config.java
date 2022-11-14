// package com.security.digestAuth.config;
//
// import java.sql.SQLException;
//
// import org.h2.tools.Server;
// import org.springframework.context.annotation.Bean;
// import org.springframework.context.annotation.Configuration;
//
// @Configuration
// public class H2Config {
// 	@Bean(initMethod = "start", destroyMethod = "stop")
// 	public Server h2Server() throws SQLException {
// 		return Server.createTcpServer("-tcp", "-tcpAllowOthers", "-tcpPort", "9092");
// 	}
// }

package com.example.configrepo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.config.server.EnableConfigServer;

@SpringBootApplication
@EnableConfigServer
public class ConfigRepoApplication {

	public static void main(String[] args) {
		SpringApplication.run(ConfigRepoApplication.class, args);
	}
}

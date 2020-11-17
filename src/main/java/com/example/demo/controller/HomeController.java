package com.example.demo.controller;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import com.example.demo.service.Argon2Service;
import com.example.demo.service.BcryptService;
import com.example.demo.service.PBKFD2Service;
import com.example.demo.service.SHAService;
import com.example.demo.service.SaltedMD5Service;
import com.example.demo.service.ScryptService;

@RestController
@RequestMapping("/")
public class HomeController {
	
	@Autowired
	SaltedMD5Service saltedMD5;
	
	@Autowired
	SHAService sha;
	
	@Autowired
	PBKFD2Service pbkfd2;
	
	@Autowired
	BcryptService bcrypt;
	
	@Autowired
	ScryptService scrypt;
	
	@Autowired
	Argon2Service argon2;
	
	@GetMapping
	public ModelAndView home() {
		return new ModelAndView("index");
	}
	
	@GetMapping("/encode")
	public Map<String, Object> encode(@RequestParam("password") String password, @RequestParam("salt") String salt) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
		
		Map<String, Object> results = new HashMap<>();
		
		results.put("MD5", saltedMD5.generate(password, salt));
		results.put("SHA", sha.generate(password, salt));
		results.put("PBKFD2", pbkfd2.generate(password, salt));
		results.put("Bcrypt", bcrypt.generate(password, "$2a$10$" + salt));
		results.put("Scrypt", scrypt.generate(password, salt));
		
		return results;
	}
}

package com.example.demo.service;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.example.demo.algorithm.BCrypt;

@Service
public class BcryptService {
	public Map<String, Object> generate(String passwordToHash, String salt) throws NoSuchAlgorithmException {
		Map<String, Object> results = new HashMap<>();
		
		Instant start = Instant.now();
		String generatedSecuredPasswordHash = BCrypt.hashpw(passwordToHash, salt);
		Instant end = Instant.now();
        Long time = Duration.between(start, end).toNanos();
        Long time1 = Duration.between(start, end).toMillis();
        results.put("time", time + " ns");
        results.put("time-ms", time1 + " ms");
        results.put("hash", generatedSecuredPasswordHash);
        
		return results;
	}
}

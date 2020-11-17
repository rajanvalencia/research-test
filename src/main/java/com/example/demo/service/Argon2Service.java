package com.example.demo.service;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class Argon2Service {
	
	public static Map<String, Object> generate(String passwordToHash) {

		Argon2PasswordEncoder encoder = 
				new Argon2PasswordEncoder(21 /*salt  length*/, 128 /*hash length*/, 1 /*parallelism*/, 1 << 12 /* memory */, 3 /*iteration*/);

		Map<String, Object> results = new HashMap<>();
		
		Instant start = Instant.now();
        String hash = encoder.encode(passwordToHash);
        Instant end = Instant.now();
        Long time = Duration.between(start, end).toNanos();
        Long time1 = Duration.between(start, end).toMillis();
        results.put("time", time + " ns");
        results.put("time-ms", time1 + " ms");
        results.put("hash", hash);
        
        return results;
	}
	
	public static void main(String[] args) {
		Map<String, Object> results = generate("password");
		
		System.out.format("Time (ns): %s\nTime (ms): %s\nLength: %s\nEncoded Hash: %s\n", 
				results.get("time"), results.get("time-ms"), results.get("hash").toString().length(), results.get("hash"));
	}
}

package com.example.demo.service;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;

@Service
public class Argon2Service {
	
	public static Map<String, Object> generate(String passwordToHash) {
		
		Argon2 argon2 = Argon2Factory.create();

		Instant start = Instant.now();
		String hash = argon2.hash(22 /* iterations */, 65536 /* memory */, 1 /* parallelism */, passwordToHash.getBytes() /* salt */);
        Instant end = Instant.now();
        Long time = Duration.between(start, end).toNanos();
        Long time1 = Duration.between(start, end).toMillis();
        
        Map<String, Object> results = new HashMap<>();
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

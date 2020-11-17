package com.example.demo.service;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

import com.example.demo.utils.SCryptUtils;

@Service
public class ScryptService {
    public Map<String, Object> generate(String passwordToHash, String salt) {
    	Map<String, Object> results = new HashMap<>();
		
		Instant start = Instant.now();
        String generatedSecuredPasswordHash = SCryptUtils.scrypt(passwordToHash, salt, 16, 16, 16);
        Instant end = Instant.now();
        Long time = Duration.between(start, end).toNanos();
        Long time1 = Duration.between(start, end).toMillis();
        results.put("time", time + " ns");
        results.put("time-ms", time1 + " ms");
        results.put("hash", generatedSecuredPasswordHash);
        
        return results;
    }
}

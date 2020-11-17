package com.example.demo.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.stereotype.Service;

@Service
public class SHAService {

	public Map<String, Object> generate(String passwordToHash, String salt) throws NoSuchAlgorithmException {
		
		Map<String, Object> results = new HashMap<>();
		
        Instant start = Instant.now();
        String securePassword = get_SHA_1_SecurePassword(passwordToHash, salt.getBytes());
        Instant end = Instant.now();
        Long time = Duration.between(start, end).toNanos();
        Long time1 = Duration.between(start, end).toMillis();
        results.put("sha-1-time", time + " ns");
        results.put("sha-1-time-ms", time1 + " ms");
        results.put("sha-1-hash", securePassword);
        
        start = Instant.now();
        securePassword = get_SHA_256_SecurePassword(passwordToHash, salt.getBytes());
        end = Instant.now();
        time = Duration.between(start, end).toNanos();
        time1 = Duration.between(start, end).toMillis();
        results.put("sha-256-time", time + " ns");
        results.put("sha-256-time-ms", time1 + " ms");
        results.put("sha-256-hash", securePassword);
        
        start = Instant.now();
        securePassword = get_SHA_384_SecurePassword(passwordToHash, salt.getBytes());
        end = Instant.now();
        time = Duration.between(start, end).toNanos();
        time1 = Duration.between(start, end).toMillis();
        results.put("sha-384-time", time + " ns");
        results.put("sha-384-time-ms", time1 + " ms");
        results.put("sha-384-hash", securePassword);
         
        start = Instant.now();
        securePassword = get_SHA_512_SecurePassword(passwordToHash, salt.getBytes());
        end = Instant.now();
        time = Duration.between(start, end).toNanos();
        time1 = Duration.between(start, end).toMillis();
        results.put("sha-512-time", time + " ns");
        results.put("sha-512-time-ms", time1 + " ms");
        results.put("sha-512-hash", securePassword);
        
        return results;
    }
 
    private static String get_SHA_1_SecurePassword(String passwordToHash, byte[] salt) {
        String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(salt);
            byte[] bytes = md.digest(passwordToHash.getBytes());
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } 
        catch (NoSuchAlgorithmException e) 
        {
            e.printStackTrace();
        }
        return generatedPassword;
    }
     
    private static String get_SHA_256_SecurePassword(String passwordToHash, byte[] salt) {
    	String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(salt);
            byte[] bytes = md.digest(passwordToHash.getBytes());
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } 
        catch (NoSuchAlgorithmException e) 
        {
            e.printStackTrace();
        }
        return generatedPassword;
    }
     
    private static String get_SHA_384_SecurePassword(String passwordToHash, byte[] salt) {
    	String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-384");
            md.update(salt);
            byte[] bytes = md.digest(passwordToHash.getBytes());
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } 
        catch (NoSuchAlgorithmException e) 
        {
            e.printStackTrace();
        }
        return generatedPassword;
    }
     
    private static String get_SHA_512_SecurePassword(String passwordToHash, byte[] salt) {
    	String generatedPassword = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            md.update(salt);
            byte[] bytes = md.digest(passwordToHash.getBytes());
            StringBuilder sb = new StringBuilder();
            for(int i=0; i< bytes.length ;i++)
            {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }
            generatedPassword = sb.toString();
        } 
        catch (NoSuchAlgorithmException e) 
        {
            e.printStackTrace();
        }
        return generatedPassword;
    }
     
    private static byte[] getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[16];
        sr.nextBytes(salt);
        return salt;
    }
}

package com.API.RSSSIDE;

import java.io.UnsupportedEncodingException;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.atomic.AtomicLong;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

@RestController
public class ApiController {
	
	// アルゴリズム/ブロックモード/パディング方式
	private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
	// 暗号化＆復号化で使用する鍵_暗号化キー
	private static final String ENCRYPT_KEY = "yourEncryptKey01";
	// 初期ベクトル
	private static final String INIT_VECTOR = "yourInitVector01";
	private static final String template = "This is a test method form %s！";
	private final AtomicLong counter = new AtomicLong();

//	private final IvParameterSpec iv = new IvParameterSpec(INIT_VECTOR.getBytes());
//	private final SecretKeySpec key = new SecretKeySpec(ENCRYPT_KEY.getBytes(), "AES");
	
	@GetMapping("/callRssideApi")
	public String callRssideApi(@RequestParam(value = "kbn", defaultValue = "HTTP") String kbn) {
		
		if ("heroku".equals(kbn)) {
			Response response = new Response(counter.incrementAndGet(), String.format(template, kbn));
			System.out.println("■■■■■■■■■■　callRssideApi　：　Response　：" + response.toString());
			return String.format(template, kbn);
		}
		
	    HttpHeaders headers = new HttpHeaders();// ヘッダ部
	    RestTemplate restTemplate = new RestTemplate();
	    ResponseEntity<String> response;
	    HttpEntity<String> entity;
	    String requestBobgJson = "";
	    String responseJson = "";
	    // String strToken="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZWFtU3RvcmVBcGkiLCJqdGkiOiI3ZDQyODdiYS0wNWUxLTQ0MzctYjgwNC00YzFlOWY0ZDJjODgiLCJzaWQiOiJURVNUIiwiaXNzIjoiVEVTVCIsImF1ZCI6IlRlYW1TdG9yZUFwaSJ9.oyzDap8Znl-ET2-2x5GLl4wzNJwTHZGOauE-7LuGRYE";
	    
	    try {
		    // final String url = "https://192.168.104.203:60001/api/StoredTest?count=5";
		    final String url = "https://www.google.co.jp/imghp?hl=ja&tab=ri&ogbl";
		    headers = new HttpHeaders();// ヘッダ部
		    // headers.setBearerAuth(tokenResponse);
		    headers.setContentType(MediaType.APPLICATION_JSON);
		    // headers.set("Authorization", "Bearer " + strToken); // トークン
		    // headers.add("Authorization", "Bearer " + strToken); // トークン
		    System.out.println("■■■■■■■■■■　callRssideApi　：　headers　：" + headers.toString());
		    entity = new HttpEntity<String>(requestBobgJson, headers);
		    response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class, "");
		    responseJson = response.getBody();
	    } catch (Exception e) {
	         e.printStackTrace();
	         responseJson = e.getMessage();
	         return responseJson;
	     }
	    
		return responseJson;
	}
	
	@GetMapping("/callRssideApiHttp")
	public String callRssideApiHttp(@RequestParam(value = "kbn", defaultValue = "HTTP") String kbn) {
		
		if ("heroku".equals(kbn)) {
			Response response = new Response(counter.incrementAndGet(), String.format(template, kbn));
			System.out.println("■■■■■■■■■■　callRssideApi　：　Response　：" + response.toString());
			return String.format(template, kbn);
		}
		
	    HttpHeaders headers = new HttpHeaders();// ヘッダ部
	    RestTemplate restTemplate = new RestTemplate();
	    ResponseEntity<String> response;
	    HttpEntity<String> entity;
	    String requestBobgJson = "";
	    String responseJson = "";
	    String strToken="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUZWFtU3RvcmVBcGkiLCJqdGkiOiI3ZDQyODdiYS0wNWUxLTQ0MzctYjgwNC00YzFlOWY0ZDJjODgiLCJzaWQiOiJURVNUIiwiaXNzIjoiVEVTVCIsImF1ZCI6IlRlYW1TdG9yZUFwaSJ9.oyzDap8Znl-ET2-2x5GLl4wzNJwTHZGOauE-7LuGRYE";
	    
	    try {
		    // final String url = "https://192.168.104.203:60001/api/StoredTest?count=5";
	    	final String url = "http://192.168.104.11:60000/api/StoredTest?count=5";
		    headers = new HttpHeaders();// ヘッダ部
		    // headers.setBearerAuth(tokenResponse);
		    headers.setContentType(MediaType.APPLICATION_JSON);
		    // headers.set("Authorization", "Bearer " + strToken); // トークン
		    headers.add("Authorization", "Bearer " + strToken); // トークン
		    System.out.println("■■■■■■■■■■　callRssideApi　：　headers　：" + headers.toString());
		    entity = new HttpEntity<String>(requestBobgJson, headers);
		    response = restTemplate.exchange(url, HttpMethod.POST, entity, String.class, "");
		    responseJson = response.getBody();
	    } catch (Exception e) {
	         e.printStackTrace();
	         responseJson = e.getMessage();
	         return responseJson;
	     }
	    
		return responseJson;
	}
    /********************* サンプルコードをいったんコメントアウトとする***********************

	@GetMapping("/getting")
	public String getting(@RequestParam(value = "name", defaultValue = "HTTP") String name) {
		Response response = new Response(counter.incrementAndGet(), String.format(template, name));
		
		return encrypter(response.toString());
	}
	
	// Tokenを作成する処理
	@GetMapping("/generateToken")
	public String generateToken() {
		 Long EXPIRATION_TIME = 1000L * 60L * 10L;
	     String secretKey = "secret";
	     Date issuedAt = new Date(); 
	     // 利用開始時間
	     Date notBefore = new Date(issuedAt.getTime());
	     // 有効期限
	     Date expiresAt = new Date(issuedAt.getTime() + EXPIRATION_TIME);
         String tokenResult = "";
         
	     try {
	         Algorithm algorithm = Algorithm.HMAC256(secretKey);
	         String token = JWT.create()
	             // registered claims
	             //.withJWTId("jwtId")        //"jti" : JWT ID
	             //.withAudience("audience")  //"aud" : Audience
	             //.withIssuer("issuer")      //"iss" : Issuer
	             .withSubject("test")         //"sub" : Subject
	             .withIssuedAt(issuedAt)      //"iat" : Issued At
	             .withNotBefore(notBefore)    //"nbf" : Not Before
	             .withExpiresAt(expiresAt)    //"exp" : Expiration Time
	             //private claims
	             .withClaim("X-AUTHORITIES", "aaa")
	             .withClaim("X-USERNAME", "bbb")
	             .sign(algorithm);
	         System.out.println("generate token : " + token);
	         tokenResult = token;
	     } catch (UnsupportedEncodingException e) {
	         e.printStackTrace();
	     }
	     return tokenResult;
	}
	
	// Tokenを認証する処理
	@GetMapping("/verifyToken")
	public String verifyToken(@RequestParam(value = "token", defaultValue = "HTTP") String token) {
	    String secretKey = "secret";
	    String verifyResult = "";
	    try {
	        Algorithm algorithm = Algorithm.HMAC256(secretKey);
	        JWTVerifier verifier = JWT.require(algorithm).build();

	        DecodedJWT jwt = verifier.verify(token);

	        // registered claims
	        String subject = jwt.getSubject();
	        Date issuedAt = jwt.getIssuedAt();
	        Date notBefore = jwt.getNotBefore();
	        Date expiresAt = jwt.getExpiresAt();
	        System.out.println("subject : [" + subject + "] issuedAt : [" + issuedAt.toString() + "] notBefore : [" + notBefore.toString() + "] expiresAt : [" + expiresAt.toString() + "]");
	        // subject : [test] issuedAt : [Thu Apr 12 13:19:00 JST 2018] notBefore : [Thu Apr 12 13:19:00 JST 2018] expiresAt : [Thu Apr 12 13:29:00 JST 2018]

	        // private claims
	        String authorities = jwt.getClaim("X-AUTHORITIES").asString();
	        String username = jwt.getClaim("X-USERNAME").asString();
	        System.out.println("private claim  X-AUTHORITIES : [" + authorities + "] X-USERNAME : [" + username + "]");
	        // private claim  X-AUTHORITIES : [aaa] X-USERNAME : [bbb]
	        verifyResult = "SUCCESS";
	        
	    } catch (UnsupportedEncodingException | JWTVerificationException e) {
	    	verifyResult = "ERROR";
	        e.printStackTrace();
	    }
	    
	    return verifyResult;
	}
	
	private String encrypter(String inputStr) {
	    //////////// 暗号化処理 ///////////////////////
	    String encryptedToken = "";
	    IvParameterSpec ivP = new IvParameterSpec(INIT_VECTOR.getBytes());
	    SecretKeySpec sKey = new SecretKeySpec(ENCRYPT_KEY.getBytes(), "AES");
	    
	    try {
	    	Cipher encrypter = Cipher.getInstance(ALGORITHM);
			encrypter.init(Cipher.ENCRYPT_MODE, sKey, ivP);
			byte[] byteToken = encrypter.doFinal(inputStr.getBytes());
			encryptedToken =  new String(Base64.getEncoder().encode(byteToken));
		} catch (Exception e) {
			e.printStackTrace();
		}
	    
	    return encryptedToken;
	}
	*/
}

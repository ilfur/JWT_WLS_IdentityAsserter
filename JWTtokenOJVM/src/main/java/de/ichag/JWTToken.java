/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package de.ichag;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author MPFEIFER
 */
public class JWTToken {

    public static String genToken(String username) {
        String privateAlias = "";
        try {
            privateAlias = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException ex) {
            System.err.println(ex.getMessage());
        }
        String tokenStr = "";

        Algorithm algorithm = Algorithm.HMAC256(privateAlias);
        try {
            final Instant now = Instant.now();

            tokenStr = JWT.create()
                    .withIssuer(privateAlias)
                    .withAudience("http://" + privateAlias)
                    .withSubject(username)
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(now.plus(3600, ChronoUnit.SECONDS)))
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            System.err.println(exception.getMessage());
        }
        return tokenStr;
    }

    public static String checkToken(String jwttoken) {
        String userName = null;
        DecodedJWT jwt = null;
        //List<String> grpList = null;
        jwt = JWT.decode(jwttoken);
        Algorithm algorithm = Algorithm.HMAC256(jwt.getIssuer());
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(jwt.getIssuer())
                .acceptLeeway(1) //1 sec for nbf and iat
                .acceptExpiresAt(5) //5 secs for exp
                .build(); //Reusable verifier instance
        jwt = verifier.verify(jwttoken);
        //Claim grpClaim = jwt.getClaim("grp");
        //grpList = grpClaim.asList(java.lang.String.class);
        userName = jwt.getSubject();
        return userName;
    }

    public static String decodeToken(String jwttoken) {
        String userName = null;
        DecodedJWT jwt = null;
        //List<String> grpList = null;
        jwt = JWT.decode(jwttoken);
        //Claim grpClaim = jwt.getClaim("grp");
        //grpList = grpClaim.asList(java.lang.String.class);
        userName = jwt.getSubject();
        return userName;
    }

    public static String printToken(String jwttoken) {
        Base64 base64 = new Base64();
        String[] sub = jwttoken.split("\\.");
        String fullString = "";
        System.out.println(jwttoken);
        for (int i = 0; i < sub.length; i++) {
            System.out.println(sub[i]);
            fullString = fullString.concat(new String(base64.decode(sub[i].getBytes()))).concat("\n");
            System.out.println(fullString);
        }
        return fullString;
    }
}

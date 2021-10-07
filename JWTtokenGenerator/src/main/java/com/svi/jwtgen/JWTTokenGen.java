/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.svi.jwtgen;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import java.io.FileInputStream;
import java.net.InetAddress;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import static java.security.Policy.getPolicy;
import static java.util.Collections.list;

import java.util.Collections;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonArrayBuilder;
import javax.json.JsonBuilderFactory;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonValue;
import javax.ws.rs.Consumes;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.net.UnknownHostException;
import java.security.CodeSource;
import java.security.Permission;
import java.security.cert.Certificate;
import java.security.PermissionCollection;
import java.security.Principal;
import java.security.ProtectionDomain;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import javax.security.auth.Subject;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.security.jacc.PolicyContext;
import javax.security.jacc.PolicyContextException;
import javax.security.jacc.WebRoleRefPermission;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;

/**
 *
 * @author MPFEIFER
 *
 *
 * // Specifies the path to the RESTful service
 * @Path("/helloworld") public class helloWorld {
 *
 * // Specifies that the method processes HTTP GET requests
 * @GET
 * @Produces("text/plain") public String sayHello() { return "Hello World!"; } }
 */
//@Path("/oauth2")
@Path("/token")
public class JWTTokenGen {

    private static final JsonBuilderFactory JSON = Json.createBuilderFactory(null);

    Logger logger = Logger.getLogger(this.getClass().getName());

    @Context
    SecurityContext securityContext;

    @Path("/validate")
    @GET
    @Produces("application/json")
    public String validateToken(@HeaderParam("Authorization") String tokenStr) throws Exception {
        tokenStr = tokenStr.substring("Bearer ".length());
        try {
        DecodedJWT jwt = null;
        jwt = JWT.decode(tokenStr);
        Algorithm algorithm = Algorithm.HMAC256(jwt.getIssuer());
        JWTVerifier verifier = JWT.require(algorithm)
                .withIssuer(jwt.getIssuer())
                .acceptLeeway(1) //1 sec for nbf and iat
                .acceptExpiresAt(5) //5 secs for exp
                .build(); //Reusable verifier instance
        jwt = verifier.verify(tokenStr);
        } catch (Exception e) {
            return "{\"valid\" : false, \"reason\":\""+e.getMessage()+"\"}";
        }

        return "{\"valid\" : true}";
    }

    @Path("/noGroups")
    @GET
    @Produces("application/jwt")
    public String genTokenNoGroups() {
        String privateAlias;
        try {
            privateAlias = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException ex) {
            Logger.getLogger(JWTTokenGen.class.getName()).log(Level.SEVERE, null, ex);
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        String tokenStr = "";
        //JsonObjectBuilder oauthBuild = JSON.createObjectBuilder();
        JsonObjectBuilder jwtBuild = JSON.createObjectBuilder();

        if (securityContext.getUserPrincipal() == null) {
            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
        }

        Algorithm algorithm = Algorithm.HMAC256(privateAlias);
        try {
            final Instant now = Instant.now();

            tokenStr = JWT.create()
                    .withIssuer(privateAlias)
                    .withAudience("http://" + privateAlias)
                    .withSubject(securityContext.getUserPrincipal().getName())
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(now.plus(3600, ChronoUnit.SECONDS)))
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
            logger.warning("invalid signing ocnfiguration or could not convert Claims");
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }

        /*
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance("JKS");
        } catch (KeyStoreException ex) {
            Logger.getLogger(JWTTokenGen.class.getName()).log(Level.SEVERE, null, ex);
        }
        keystore.load(new FileInputStream("/path/to/jks"),
                "weblogic123".toCharArray());
        PrivateKey privateKey
                = (PrivateKey) keystore.getKey(privateAlias,
                        "weblogic123".toCharArray());
        X509Certificate cert
                = (X509Certificate) keystore.getCertificate(certAlias);
        Algorithm algorithmRS = Algorithm.RSA256(publicKey, privateKey);
         */
        // returning a oauth JSON doc instead of a pure JWT token if required
        /*JsonObject oauthToken = oauthBuild.add("access_token", tokenStr)
                .add("token_type", "Bearer")
                .add("expires_in", "3600")
                .build();
        return oauthToken.toString();*/
        return tokenStr;
    }
    
    /*
    @Path("/withGroups")
    @GET
    @Produces("application/jwt")

    public String genToken() {
        String privateAlias;
        try {
            privateAlias = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException ex) {
            Logger.getLogger(JWTTokenGen.class.getName()).log(Level.SEVERE, null, ex);
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }
        String tokenStr = "";
        //JsonObjectBuilder oauthBuild = JSON.createObjectBuilder();
        JsonObjectBuilder jwtBuild = JSON.createObjectBuilder();
        Set<String> roles = new HashSet<String>();

        try {
            Subject subject = (Subject) PolicyContext.getContext("javax.security.auth.Subject.container");

            if (subject != null) {
                logger.info("Obtained subject from context.\n");

                Iterator<Principal> it = subject.getPrincipals().iterator();
                String prName = "";
                while (it.hasNext()) {
                    prName = it.next().getName();
                    if (securityContext.isUserInRole(prName) && (!prName.equals(securityContext.getUserPrincipal().getName()))) {
                        roles.add(prName);
                        logger.info("Role found: " + prName);
                    }
                }

            } else {
                throw new WebApplicationException(Response.Status.UNAUTHORIZED);
            }
        } catch (PolicyContextException e) {
            logger.log(Level.WARNING, "Problems with Policy Context:", e);
            throw new WebApplicationException(Response.Status.INTERNAL_SERVER_ERROR);
        }

        if (securityContext.getUserPrincipal() == null) {
            throw new WebApplicationException(Response.Status.UNAUTHORIZED);
        }

        Algorithm algorithm = Algorithm.HMAC256(privateAlias);
        try {
            final Instant now = Instant.now();

            tokenStr = JWT.create()
                    .withIssuer(privateAlias)
                    .withAudience("http://" + privateAlias)
                    .withSubject(securityContext.getUserPrincipal().getName())
                    .withIssuedAt(Date.from(now))
                    .withExpiresAt(Date.from(now.plus(3600, ChronoUnit.SECONDS)))
                    .withClaim("grp", new ArrayList<String>(roles))
                    .sign(algorithm);
        } catch (JWTCreationException exception) {
            //Invalid Signing configuration / Couldn't convert Claims.
        }
        
        return tokenStr;
    }
*/

}

package com.svi.asserter;

import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.login.AppConfigurationEntry;
import weblogic.management.security.ProviderMBean;
import weblogic.security.service.ContextHandler;
import weblogic.security.spi.AuthenticationProviderV2;
import weblogic.security.spi.IdentityAsserterV2;
import weblogic.security.spi.IdentityAssertionException;
import weblogic.security.spi.PrincipalValidator;
import weblogic.security.spi.SecurityServices;
import javax.servlet.http.HttpServletRequest;
import java.net.URL;
import java.util.HashMap;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;

import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;

public final class JWTtokenIdentityAsserterProviderImpl implements AuthenticationProviderV2, IdentityAsserterV2 {

    final static private String TOKEN_TYPE = "Authorization";
    final static private String TOKEN_PREFIX = "Bearer ";
    Logger logger = Logger.getLogger(this.getClass().getName());

    private String description;

    public void initialize(ProviderMBean mbean, SecurityServices services) {
        logger.warning("JWTtokenIdentityAsserterProviderImpl.initialize");
        JWTtokenIdentityAsserterMBean myMBean = (JWTtokenIdentityAsserterMBean) mbean;
        description = myMBean.getDescription() + "\n" + myMBean.getVersion();

    }

    public IdentityAsserterV2 getIdentityAsserter() {
        return this;
    }

    public AppConfigurationEntry getLoginModuleConfiguration() {
        return null;
    }

    public AppConfigurationEntry getAssertionModuleConfiguration() {
        return null;
    }

    public PrincipalValidator getPrincipalValidator() {
        return null;
    }

    public String getDescription() {
        return description;
    }

    public void shutdown() {
        logger.warning("JWTtokenIdentityAsserterProviderImpl.shutdown");
    }

    public CallbackHandler assertIdentity(String type, Object token, ContextHandler context) throws IdentityAssertionException {
        logger.warning("JWTtokenIdentityAsserterProviderImpl.assertIdentity");
        logger.warning("\tType\t\t= " + type);
        logger.warning("\tToken\t\t= " + token);

        Object requestValue = context.getValue("com.bea.contextelement.servlet.HttpServletRequest");
        if ((requestValue == null) || (!(requestValue instanceof HttpServletRequest))) {
            logger.warning("do nothing");
        } else {
            HttpServletRequest request = (HttpServletRequest) requestValue;
            java.util.Enumeration names = request.getHeaderNames();
            while (names.hasMoreElements()) {
                String name = (String) names.nextElement();
                logger.warning(name + ":" + request.getHeader(name));
            }
        }

        // check the token type
        if (!(TOKEN_TYPE.equals(type))) {
            String error
                    = "JWTtokenIdentityAsserter received unknown token type \"" + type + "\"."
                    + " Expected " + TOKEN_TYPE;
            logger.warning("\tError: " + error);
            throw new IdentityAssertionException(error);
        }

        // make sure the token is an array of bytes
        if (!(token instanceof byte[])) {
            String error
                    = "JWTtokenIdentityAsserter received unknown token class \"" + token.getClass() + "\"."
                    + " Expected a byte[].";
            logger.warning("\tError: " + error);
            throw new IdentityAssertionException(error);
        }

        // convert the array of bytes to a string
        byte[] tokenBytes = (byte[]) token;
        if (tokenBytes == null || tokenBytes.length < 1) {
            String error
                    = "JWTtokenIdentityAsserter received empty token byte array";
            logger.warning("\tError: " + error);
            throw new IdentityAssertionException(error);
        }

        String tokenStr = new String(tokenBytes);

        // make sure the string contains "username=someusername
        if (!(tokenStr.startsWith(TOKEN_PREFIX))) {
            String error
                    = "JWTtokenIdentityAsserter received unknown token string \"" + type + "\"."
                    + " Expected " + TOKEN_PREFIX + "<jwt token>";
            logger.warning("\tError: " + error);
            throw new IdentityAssertionException(error);
        }

        // extract the username from the token
        String jwttoken = tokenStr.substring(TOKEN_PREFIX.length());
        logger.warning("\ttoken content\t= " + jwttoken);
        String userName = null;
        DecodedJWT jwt = null;
        //List<String> grpList = null;
        try {
            jwt = JWT.decode(jwttoken);
            try {
                Algorithm algorithm = Algorithm.HMAC256(jwt.getIssuer());
                JWTVerifier verifier = JWT.require(algorithm)
                        .withIssuer(jwt.getIssuer())
                        .acceptLeeway(1) //1 sec for nbf and iat
                        .acceptExpiresAt(5) //5 secs for exp
                        .build(); //Reusable verifier instance
                jwt = verifier.verify(jwttoken);
            } catch (JWTVerificationException exception) {
                //Invalid signature/claims
                logger.warning("uh-oh, JWT token validation failed: " + exception.getMessage());
                throw new IdentityAssertionException("uh-oh, JWT Token validation failed: " + exception.getMessage());
            }

        } catch (JWTDecodeException exception) {
            logger.warning("uh-oh, invalid JWT token: " + exception.getMessage());
            throw new IdentityAssertionException("uh-oh, invalid JWT token: " + exception.getMessage());
        }
        //Claim grpClaim = jwt.getClaim("grp");
        //grpList = grpClaim.asList(java.lang.String.class);
        userName = jwt.getSubject();
        // store it in a callback handler that authenticators can use
        // to retrieve the username.
        return new JWTtokenCallbackHandlerImpl(userName);
    }

}

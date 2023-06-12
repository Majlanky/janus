/*
 * Copyright 2022 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.groocraft.janus.security;

import com.groocraft.janus.exception.UnknownIssuerException;
import com.nimbusds.jwt.JWTParser;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import static org.springframework.security.oauth2.jwt.JwtClaimNames.ISS;

/**
 * Authentication resolver for JWT supporting multitenancy. Authentication resolves if the given JWT is issued by known issuer and then
 * pick proper provider to check validity and resolve {@link org.springframework.security.core.Authentication} based on the configuration
 * of the known IdP.
 *
 * @author mbabicky-ext
 */
@Slf4j
@AllArgsConstructor
public class MultiIdentityProviderAuthenticationResolver implements AuthenticationManagerResolver<HttpServletRequest> {

    private final IdentityProviders config;
    private final BearerTokenResolver resolver = new DefaultBearerTokenResolver();
    private final ConcurrentHashMap<String, AuthenticationManager> authenticationManagers = new ConcurrentHashMap<>();

    /**
     * {@inheritDoc}
     *
     * @param request must not be {@literal null}
     * @return authentication manager if the token in the given {@code request} is from a known issuer and valid. Throws an exception
     * otherwise
     */
    @Override
    @NonNull
    public AuthenticationManager resolve(@NonNull HttpServletRequest request) {
        String issuer = getIssuer(request);
        IdentityProvider idp = config.getKnownIdPs().get(issuer);
        if (idp != null) {
            return authenticationManagers.computeIfAbsent(issuer, i -> jwtAuthProvider(idp)::authenticate);
        } else {
            throw new UnknownIssuerException(issuer);
        }
    }

    /**
     * Resolves an issuer of token in the given {@code request}
     *
     * @param request must not be {@literal null}
     * @return issuer of token. Throws an exception otherwise.
     */
    @NonNull
    private String getIssuer(@NonNull HttpServletRequest request) {
        try {
            return JWTParser.parse(resolver.resolve(request)).getJWTClaimsSet().getStringClaim(ISS);
        } catch (ParseException e) {
            throw new InvalidBearerTokenException("Unable to resolve issuer from the given JWT", e);
        }
    }

    /**
     * @param configuration must not be {@literal null}
     * @return authentication provider that is able to resolve {@link org.springframework.security.core.Authentication} of IdP from the given
     * {@code configuration}. Throws an exception otherwise.
     */
    @NonNull
    private JwtAuthenticationProvider jwtAuthProvider(@NonNull IdentityProvider configuration) {
        JwtDecoder jwtDecoder;
        if (configuration.getJwkSetUri() != null) {
            NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(configuration.getJwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.from(configuration.getJwsAlgorithm())).build();
            String issuerUri = configuration.getIssuerUri();
            if (issuerUri != null) {
                decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
            }
            jwtDecoder = decoder;
        } else {
            try {
                RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(KeySpec.getDecoded(configuration.readPublicKey())));
                jwtDecoder = NimbusJwtDecoder.withPublicKey(publicKey)
                        .signatureAlgorithm(SignatureAlgorithm.from(configuration.getJwsAlgorithm())).build();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException ex) {
                throw new IllegalArgumentException("Unable to configure identity provider " + configuration.getId(), ex);
            }
        }
        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(JanusJwtGrantedAuthoritiesConverter.from(configuration));
        authenticationProvider.setJwtAuthenticationConverter(converter);
        return authenticationProvider;
    }

}

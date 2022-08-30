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
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtGrantedAuthoritiesConverterAdapter;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.util.HashMap;
import java.util.Map;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
@AllArgsConstructor
public class ReactiveMultiIdentityProviderAuthenticationResolver implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

    private final IdentityProviders configuration;
    private final Map<String, ReactiveAuthenticationManager> managers = new HashMap<>();

    @Override
    public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
        return Mono.just(this::authenticate);
    }

    @NonNull
    private Mono<Authentication> authenticate(@NonNull Authentication authentication) {
        Assert.isTrue(authentication instanceof BearerTokenAuthenticationToken,
                "Authentication must be of type BearerTokenAuthenticationToken");
        BearerTokenAuthenticationToken token = (BearerTokenAuthenticationToken) authentication;
        try {
            return managers.computeIfAbsent(getIssuer(token), this::createAuthenticationManager).authenticate(authentication);
        } catch (ParseException ex) {
            return Mono.error(() -> new InvalidBearerTokenException(ex.getMessage(), ex));
        } catch (InvalidBearerTokenException ex) {
            return Mono.error(() -> ex);
        }
    }

    @NonNull
    private ReactiveAuthenticationManager createAuthenticationManager(@NonNull String issuer) {
        JwtReactiveAuthenticationManager authenticationManager = new JwtReactiveAuthenticationManager(getDecoder(issuer));
        ReactiveJwtAuthenticationConverter converter = new ReactiveJwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(
                new ReactiveJwtGrantedAuthoritiesConverterAdapter(JanusJwtGrantedAuthoritiesConverter.from(this.configuration.getKnownIdPs()
                        .get(issuer))));
        authenticationManager.setJwtAuthenticationConverter(converter);
        return authenticationManager;
    }

    @NonNull
    private ReactiveJwtDecoder getDecoder(@NonNull String issuer) {
        IdentityProvider identityProvider = this.configuration.getKnownIdPs().get(issuer);
        if (identityProvider == null) {
            throw new UnknownIssuerException(issuer);
        }
        if (identityProvider.getJwkSetUri() != null) {
            NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(identityProvider.getJwkSetUri())
                    .jwsAlgorithm(SignatureAlgorithm.from(identityProvider.getJwsAlgorithm())).build();
            String issuerUri = identityProvider.getIssuerUri();
            if (issuerUri != null) {
                decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
            }
            return decoder;
        } else {
            try {
                RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(KeySpec.getDecoded(identityProvider.readPublicKey())));
                return NimbusReactiveJwtDecoder.withPublicKey(publicKey)
                        .signatureAlgorithm(SignatureAlgorithm.from(identityProvider.getJwsAlgorithm())).build();
            } catch (NoSuchAlgorithmException | InvalidKeySpecException | IOException ex) {
                throw new IllegalArgumentException("Unable to configure identity provider " + identityProvider.getId(), ex);
            }
        }
    }

    @NonNull
    private String getIssuer(@NonNull BearerTokenAuthenticationToken token) throws ParseException {
        String issuer = JWTParser.parse(token.getToken()).getJWTClaimsSet().getIssuer();
        if (issuer == null) {
            throw new InvalidBearerTokenException("Missing issuer");
        }
        return issuer;
    }

}

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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class MultiIdentityProviderAuthenticationResolverTest {

    @Mock IdentityProviders identityProviders;
    @Spy IdentityProvider identityProvider;
    @Mock HttpServletRequest request;

    static String token;
    static String differentToken;
    static String jwkSet;
    static String differentJwkSet;

    @BeforeAll
    static void setUp() throws IOException {
        token = new String(Files.readAllBytes(
            FileSystems.getDefault().getPath("", "src/test/resources").resolve("access_token.jwt")));
        differentToken = new String(Files.readAllBytes(
            FileSystems.getDefault().getPath("", "src/test/resources").resolve("diff_access_token.jwt")));
        jwkSet = new String(Files.readAllBytes(
            FileSystems.getDefault().getPath("", "src/test/resources").resolve("jwk_set.json")));
        differentJwkSet = new String(Files.readAllBytes(
            FileSystems.getDefault().getPath("", "src/test/resources").resolve("diff_jwk_set.json")));
    }

    @Test
    void testTokenFromUntrustedIssuerCasesException() {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        knownIdPs.put("https://localhost:8888/differenct/idp", identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        assertThrows(InvalidBearerTokenException.class, () -> resolver.resolve(request));
    }

    @Test
    void authenticationManagerIsResolvedForKnownIssuer(){
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        assertDoesNotThrow(() -> resolver.resolve(request));
    }

    @Test
    void authenticationManagerIsCachedByIssuer(){
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        assertSame(resolver.resolve(request), resolver.resolve(request));
    }

    @Test
    void testAuthenticationManagerValidatesByIssuer(){
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        try(MockedConstruction<RestTemplate> restTemplate = mockConstruction(RestTemplate.class, (m, c) -> {
            when(m.exchange(any(), eq(String.class))).thenReturn(ResponseEntity.ok(jwkSet));
        })) {
            AuthenticationManager manager = resolver.resolve(request);
            BearerTokenAuthenticationToken authenticationToken = mock(BearerTokenAuthenticationToken.class);
            when(authenticationToken.getToken()).thenReturn(differentToken);

            assertThrows(InvalidBearerTokenException.class, () -> manager.authenticate(authenticationToken));
        }
    }

    @Test
    void testAuthenticationManagerValidatesByJwkSet(){
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        try(MockedConstruction<RestTemplate> restTemplate = mockConstruction(RestTemplate.class, (m, c) -> {
            when(m.exchange(any(), eq(String.class))).thenReturn(ResponseEntity.ok(differentJwkSet));
        })) {
            AuthenticationManager manager = resolver.resolve(request);
            BearerTokenAuthenticationToken authenticationToken = mock(BearerTokenAuthenticationToken.class);
            when(authenticationToken.getToken()).thenReturn(token);

            assertThrows(InvalidBearerTokenException.class, () -> manager.authenticate(authenticationToken));
        }
    }

    @Test
    void testAuthenticationManagerValidatesByLocalPublicKey() throws IOException {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(identityProvider.getPublicKeyLocation()).thenReturn(new ClassPathResource("diff_signature_key.pem"));
        when(identityProvider.getRolesClaimName()).thenReturn("roles");

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        AuthenticationManager manager = resolver.resolve(request);
        BearerTokenAuthenticationToken authenticationToken = mock(BearerTokenAuthenticationToken.class);
        when(authenticationToken.getToken()).thenReturn(token);

        assertThrows(InvalidBearerTokenException.class, () -> manager.authenticate(authenticationToken));
    }

    @Test
    void testAuthenticationManagerAllowsWithValidSignatureAndParsesProperlyWithPublicKeyValidation() throws IOException {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(identityProvider.getPublicKeyLocation()).thenReturn(new ClassPathResource("signature_key.pem"));//FIXME add invalid signature
        when(identityProvider.getRolesClaimName()).thenReturn("roles");

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        AuthenticationManager manager = resolver.resolve(request);
        BearerTokenAuthenticationToken authenticationToken = mock(BearerTokenAuthenticationToken.class);
        when(authenticationToken.getToken()).thenReturn(token);

        Authentication authentication = manager.authenticate(authenticationToken);
        assertEquals("1234567890", authentication.getName());
        assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_user")));
        assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_customer")));
        assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_vip")));
    }

    @Test
    void testAuthenticationManagerAllowsWithValidSignatureAndParsesProperlyWithJwkSetValidation(){
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(request.getHeader("Authorization")).thenReturn("Bearer " + token);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);

        MultiIdentityProviderAuthenticationResolver resolver = new MultiIdentityProviderAuthenticationResolver(identityProviders);

        try(MockedConstruction<RestTemplate> restTemplate = mockConstruction(RestTemplate.class, (m, c) -> {
            when(m.exchange(any(), eq(String.class))).thenReturn(ResponseEntity.ok(jwkSet));
        })) {
            AuthenticationManager manager = resolver.resolve(request);
            BearerTokenAuthenticationToken authenticationToken = mock(BearerTokenAuthenticationToken.class);
            when(authenticationToken.getToken()).thenReturn(token);

            Authentication authentication = manager.authenticate(authenticationToken);
            assertEquals("1234567890", authentication.getName());
            assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_user")));
            assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_customer")));
            assertTrue(authentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_vip")));
        }
    }

}
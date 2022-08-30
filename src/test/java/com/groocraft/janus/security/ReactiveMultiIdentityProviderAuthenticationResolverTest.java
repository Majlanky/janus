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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.function.ThrowingSupplier;
import org.mockito.Answers;
import org.mockito.Mock;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtReactiveAuthenticationManager;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.server.ServerWebExchange;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

import reactor.core.publisher.Mono;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ReactiveMultiIdentityProviderAuthenticationResolverTest {

    @Mock IdentityProviders identityProviders;
    @Spy IdentityProvider identityProvider;
    @Mock ServerWebExchange serverWebExchange;
    @Mock BearerTokenAuthenticationToken authentication;
    @Mock(answer = Answers.RETURNS_DEEP_STUBS) WebClient webClient;

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
        when(authentication.getToken()).thenReturn(token);

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);
        Mono<Authentication> newAuthentication = resolver.resolve(serverWebExchange).block().authenticate(authentication);

        assertThrows(UnknownIssuerException.class, newAuthentication::block);
    }

    @Test
    void testUnParsableTokenCasesException() {
        when(authentication.getToken()).thenReturn("nonsence");

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);
        Mono<Authentication> newAuthentication = resolver.resolve(serverWebExchange).block().authenticate(authentication);

        assertThrows(InvalidBearerTokenException.class, newAuthentication::block);
    }

    @Test
    void authenticationManagerIsResolvedForKnownIssuer() {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);
        when(authentication.getToken()).thenReturn(token);

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);

        try (MockedStatic<WebClient> webClientStatic = mockStatic(WebClient.class)) {
            when(webClient.get().uri(any(String.class)).retrieve().bodyToMono(String.class)).thenReturn(Mono.just(jwkSet));
            webClientStatic.when(WebClient::create).thenReturn(webClient);

            Mono<Authentication> newAuthentication = resolver.resolve(serverWebExchange).block().authenticate(authentication);

            assertDoesNotThrow((ThrowingSupplier<Authentication>) newAuthentication::block);
        }
    }

    @Test
    void authenticationManagerIsCachedByIssuer() {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);
        when(authentication.getToken()).thenReturn(token);

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);

        try (MockedConstruction<JwtReactiveAuthenticationManager> constr = mockConstruction(JwtReactiveAuthenticationManager.class);
             MockedStatic<WebClient> webClientStatic = mockStatic(WebClient.class)) {
            when(webClient.get().uri(any(String.class)).retrieve().bodyToMono(String.class)).thenReturn(Mono.just(jwkSet));
            webClientStatic.when(WebClient::create).thenReturn(webClient);

            resolver.resolve(serverWebExchange).block().authenticate(authentication);
            resolver.resolve(serverWebExchange).block().authenticate(authentication);
            assertEquals(1, constr.constructed().size());
        }
    }

    @Test
    void testAuthenticationManagerValidatesByIssuer() {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);
        when(authentication.getToken()).thenReturn(token);

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);

        try (MockedStatic<WebClient> webClientStatic = mockStatic(WebClient.class)) {
            when(webClient.get().uri(any(String.class)).retrieve().bodyToMono(String.class)).thenReturn(Mono.just(differentJwkSet));
            webClientStatic.when(WebClient::create).thenReturn(webClient);

            Mono<Authentication> newAuthentication = resolver.resolve(serverWebExchange).block().authenticate(authentication);

            assertThrows(InvalidBearerTokenException.class, newAuthentication::block);
        }

    }

    @Test
    void testAuthenticationManagerValidatesByLocalPublicKey() {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(identityProvider.getPublicKeyLocation()).thenReturn(new ClassPathResource("diff_signature_key.pem"));
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(authentication.getToken()).thenReturn(token);

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);
        Mono<Authentication> newAuthentication = resolver.resolve(serverWebExchange).block().authenticate(authentication);

        assertThrows(InvalidBearerTokenException.class, newAuthentication::block);
    }

    @Test
    void testAuthenticationManagerAllowsWithValidSignatureAndParsesProperlyWithPublicKeyValidation() {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(identityProvider.getPublicKeyLocation()).thenReturn(new ClassPathResource("signature_key.pem"));
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(authentication.getToken()).thenReturn(token);

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);

        Authentication newAuthentication = resolver.resolve(serverWebExchange).block().authenticate(authentication).block();
        assertEquals("1234567890", newAuthentication.getName());
        assertTrue(newAuthentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_user")));
        assertTrue(newAuthentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_customer")));
        assertTrue(newAuthentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_vip")));
    }

    @Test
    void testAuthenticationManagerAllowsWithValidSignatureAndParsesProperlyWithJwkSetValidation() {
        Map<String, IdentityProvider> knownIdPs = new HashMap<>();
        String issuer = "https://localhost:8888/some/idp";
        knownIdPs.put(issuer, identityProvider);
        when(identityProviders.getKnownIdPs()).thenReturn(knownIdPs);
        when(identityProvider.getJwkSetUri()).thenReturn("https://localhost:23080/some/idp/protocol/openid-connect/certs");
        when(identityProvider.getRolesClaimName()).thenReturn("roles");
        when(identityProvider.getIssuerUri()).thenReturn(issuer);
        when(authentication.getToken()).thenReturn(token);

        ReactiveMultiIdentityProviderAuthenticationResolver resolver = new ReactiveMultiIdentityProviderAuthenticationResolver(identityProviders);

        try (MockedStatic<WebClient> webClientStatic = mockStatic(WebClient.class)) {
            when(webClient.get().uri(any(String.class)).retrieve().bodyToMono(String.class)).thenReturn(Mono.just(jwkSet));
            webClientStatic.when(WebClient::create).thenReturn(webClient);

            Mono<ReactiveAuthenticationManager> manager = resolver.resolve(serverWebExchange);

            Authentication newAuthentication = manager.block().authenticate(authentication).block();
            assertEquals("1234567890", newAuthentication.getName());
            assertTrue(newAuthentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_user")));
            assertTrue(newAuthentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_customer")));
            assertTrue(newAuthentication.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_vip")));
        }

    }

}
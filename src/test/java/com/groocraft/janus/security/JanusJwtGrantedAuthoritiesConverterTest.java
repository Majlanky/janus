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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.Arrays;
import java.util.Collection;

import static org.junit.jupiter.api.Assertions.assertTrue;

@ExtendWith(MockitoExtension.class)
class JanusJwtGrantedAuthoritiesConverterTest {

    @Spy IdentityProvider identityProvider;

    @Test
    void testConversion() {
        Jwt jwt = Jwt.withTokenValue("whatever")
                .headers(h -> {
                    h.put("typ", "JWT");
                    h.put("alg", "RS256");
                }).claims(c -> {
                    c.put("iss", "http://localhost:666");
                    c.put("sub", "1234567890");
                    c.put("roles", Arrays.asList("user", "admin"));
                    c.put("name", "John Doe");
                })
                .build();
        JwtGrantedAuthoritiesConverter converter = JanusJwtGrantedAuthoritiesConverter.from(identityProvider);
        Collection<GrantedAuthority> grantedAuthorities = converter.convert(jwt);
        assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("ROLE_user")));
        assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("ROLE_admin")));
    }

    @Test
    void testMissingRolesClaimDoesNotBreakProcess() {
        Jwt jwt = Jwt.withTokenValue("whatever")
                .headers(h -> {
                    h.put("typ", "JWT");
                    h.put("alg", "RS256");
                }).claims(c -> {
                    c.put("iss", "http://localhost:666");
                    c.put("sub", "1234567890");
                    c.put("name", "John Doe");
                })
                .build();
        JwtGrantedAuthoritiesConverter converter = JanusJwtGrantedAuthoritiesConverter.from(identityProvider);
        Collection<GrantedAuthority> grantedAuthorities = converter.convert(jwt);
        assertTrue(grantedAuthorities.isEmpty());
    }

    @Test
    void testConverterUsesConfiguration() {
        Jwt jwt = Jwt.withTokenValue("whatever")
                .headers(h -> {
                    h.put("typ", "JWT");
                    h.put("alg", "RS256");
                }).claims(c -> {
                    c.put("iss", "http://localhost:666");
                    c.put("sub", "1234567890");
                    c.put("testRoles", Arrays.asList("user", "admin"));
                    c.put("name", "John Doe");
                })
                .build();

        Mockito.when(identityProvider.getRolesClaimName()).thenReturn("testRoles");
        Mockito.when(identityProvider.getRolesAuthorityPrefix()).thenReturn("TEST_ROLE_");

        JwtGrantedAuthoritiesConverter converter = JanusJwtGrantedAuthoritiesConverter.from(identityProvider);
        Collection<GrantedAuthority> grantedAuthorities = converter.convert(jwt);
        assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("TEST_ROLE_user")));
        assertTrue(grantedAuthorities.contains(new SimpleGrantedAuthority("TEST_ROLE_admin")));
    }

}
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

import com.groocraft.janus.test.TestConfiguration;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.source.InvalidConfigurationPropertyValueException;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = TestConfiguration.class)
class IdentityProvidersTest {

    @Autowired
    IdentityProviders identityProviders;

    @Test
    void testParsing() {
        assertEquals(2, identityProviders.getResourceserver().size());
        assertEquals("https://localhost:8888/some/idp", identityProviders.getResourceserver().get("first").getIssuerUri());
        assertEquals("https://localhost:23080/some/idp/protocol/openid-connect/certs",
            identityProviders.getResourceserver().get("first").getJwkSetUri());
        assertEquals("little_roles", identityProviders.getResourceserver().get("first").getRolesClaimName());
        assertEquals("LITTLE_ROLE_", identityProviders.getResourceserver().get("first").getRolesAuthorityPrefix());
        assertEquals("https://localhost:8888/other/idp", identityProviders.getResourceserver().get("other").getIssuerUri());
        assertEquals("PS512", identityProviders.getResourceserver().get("other").getJwsAlgorithm());
        assertEquals("class path resource [my-key.pub]",
            identityProviders.getResourceserver().get("other").getPublicKeyLocation().toString());

        assertEquals(2, identityProviders.getKnownIdPs().size());
        assertEquals("https://localhost:8888/some/idp",
            identityProviders.getKnownIdPs().get("https://localhost:8888/some/idp").getIssuerUri());
        assertEquals("https://localhost:23080/some/idp/protocol/openid-connect/certs",
            identityProviders.getKnownIdPs().get("https://localhost:8888/some/idp").getJwkSetUri());
        assertEquals("little_roles", identityProviders.getKnownIdPs().get("https://localhost:8888/some/idp").getRolesClaimName());
        assertEquals("LITTLE_ROLE_", identityProviders.getKnownIdPs().get("https://localhost:8888/some/idp").getRolesAuthorityPrefix());
        assertEquals("https://localhost:8888/other/idp",
            identityProviders.getKnownIdPs().get("https://localhost:8888/other/idp").getIssuerUri());
        assertEquals("PS512", identityProviders.getKnownIdPs().get("https://localhost:8888/other/idp").getJwsAlgorithm());
        assertEquals("class path resource [my-key.pub]",
            identityProviders.getKnownIdPs().get("https://localhost:8888/other/idp").getPublicKeyLocation().toString());
    }

    @Test
    void testInvalidJwkSetUrlThrowsException() {
        Map<String, IdentityProvider> resourceserver = new HashMap<>();
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setJwkSetUri("nonsence://localhost:23080/some/idp/protocol/openid-connect/certs");
        resourceserver.put("first", identityProvider);
        IdentityProviders identityProviders = new IdentityProviders(resourceserver);
        assertThrows(InvalidConfigurationPropertyValueException.class, identityProviders::afterPropertiesSet);
    }

}
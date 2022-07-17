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
import org.springframework.boot.context.properties.source.InvalidConfigurationPropertyValueException;
import org.springframework.core.io.ClassPathResource;

import static org.junit.jupiter.api.Assertions.*;

class IdentityProviderTest {

    @Test
    void testInvalidPublicKeyLocationThrowsException(){
        IdentityProvider identityProvider = new IdentityProvider();
        identityProvider.setPublicKeyLocation(new ClassPathResource("non_existing.pem"));
        assertThrows(InvalidConfigurationPropertyValueException.class, () -> identityProvider.readPublicKey());
    }

}
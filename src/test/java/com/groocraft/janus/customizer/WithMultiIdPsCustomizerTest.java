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

package com.groocraft.janus.customizer;

import com.groocraft.janus.security.MultiIdentityProviderAuthenticationResolver;

import org.junit.jupiter.api.Test;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class WithMultiIdPsCustomizerTest {

    @Test
    void testCustomerSetsProperAuthenticationProvider() {
        MultiIdentityProviderAuthenticationResolver resolver = mock(MultiIdentityProviderAuthenticationResolver.class);
        OAuth2ResourceServerConfigurer<HttpSecurity> configurer = mock(OAuth2ResourceServerConfigurer.class);
        WithMultiIdPsCustomizer customizer = new WithMultiIdPsCustomizer(resolver);
        customizer.customize(configurer);
        verify(configurer).authenticationManagerResolver(resolver);
    }

}
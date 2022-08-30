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

import com.groocraft.janus.security.ReactiveMultiIdentityProviderAuthenticationResolver;

import org.junit.jupiter.api.Test;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class ReactiveWithMultiIdPsCustomizerTest {

    @Test
    void testCustomerSetsProperAuthenticationProvider() {
        ReactiveMultiIdentityProviderAuthenticationResolver resolver = mock(ReactiveMultiIdentityProviderAuthenticationResolver.class);
        ServerHttpSecurity.OAuth2ResourceServerSpec spec = mock(ServerHttpSecurity.OAuth2ResourceServerSpec.class);
        ReactiveWithMultiIdPsCustomizer customizer = new ReactiveWithMultiIdPsCustomizer(resolver);
        customizer.customize(spec);
        verify(spec).authenticationManagerResolver(resolver);
    }

}
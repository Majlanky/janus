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

import com.groocraft.janus.customizer.WithMultiIdPsCustomizer;
import com.groocraft.janus.test.TestSecurityConfiguration;
import com.groocraft.janus.test.TestSecurityWithoutDefaultConfiguration;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class JanusWebSecurityConfigurerAdapterTest {

    @Test
    void testWithMultiIdentityProviderMethodCustomizeProperly() throws Exception {
        MultiIdentityProviderAuthenticationResolver resolver = mock(MultiIdentityProviderAuthenticationResolver.class);
        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        ArgumentCaptor<Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>>> captor = ArgumentCaptor.forClass(Customizer.class);
        when(httpSecurity.oauth2ResourceServer(captor.capture())).thenReturn(httpSecurity);
        TestSecurityConfiguration configurer = new TestSecurityConfiguration();
        configurer.setWithMultiIdPsCustomizer(new WithMultiIdPsCustomizer(resolver));
        configurer.configure(httpSecurity);

        OAuth2ResourceServerConfigurer<HttpSecurity> oAuth2Configurer = mock(OAuth2ResourceServerConfigurer.class);
        captor.getValue().customize(oAuth2Configurer);
        verify(oAuth2Configurer).authenticationManagerResolver(resolver);
    }

    @Test
    void testWithMultiIdentityProviderMethodCustomizeProperlyWithoutDefault() throws Exception {
        MultiIdentityProviderAuthenticationResolver resolver = mock(MultiIdentityProviderAuthenticationResolver.class);
        HttpSecurity httpSecurity = mock(HttpSecurity.class);
        ArgumentCaptor<Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>>> captor = ArgumentCaptor.forClass(Customizer.class);
        when(httpSecurity.oauth2ResourceServer(captor.capture())).thenReturn(httpSecurity);
        TestSecurityWithoutDefaultConfiguration configurer = new TestSecurityWithoutDefaultConfiguration();
        configurer.setWithMultiIdPsCustomizer(new WithMultiIdPsCustomizer(resolver));
        configurer.configure(httpSecurity);

        OAuth2ResourceServerConfigurer<HttpSecurity> oAuth2Configurer = mock(OAuth2ResourceServerConfigurer.class);
        captor.getValue().customize(oAuth2Configurer);
        verify(oAuth2Configurer).authenticationManagerResolver(resolver);
    }

}
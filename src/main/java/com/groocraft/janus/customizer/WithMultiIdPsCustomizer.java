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

import org.springframework.lang.NonNull;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;

/**
 * Customizer for {@link OAuth2ResourceServerConfigurer} that adds support for multi IdP configuration and validation.
 *
 * @author Majlanky
 */
@RequiredArgsConstructor
@Component
public class WithMultiIdPsCustomizer implements Customizer<OAuth2ResourceServerConfigurer<HttpSecurity>> {

    private @NonNull MultiIdentityProviderAuthenticationResolver resolver;

    @Override
    public void customize(OAuth2ResourceServerConfigurer<HttpSecurity> httpSecurityOAuth2ResourceServerConfigurer) {
        httpSecurityOAuth2ResourceServerConfigurer.authenticationManagerResolver(resolver);
    }

}

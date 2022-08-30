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

import org.springframework.lang.NonNull;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import lombok.RequiredArgsConstructor;

/**
 * Customizer for {@link ServerHttpSecurity.OAuth2ResourceServerSpec} that adds support for multi IdP configuration and validation.
 *
 * @author Majlanky
 */
@RequiredArgsConstructor
public class ReactiveWithMultiIdPsCustomizer implements Customizer<ServerHttpSecurity.OAuth2ResourceServerSpec> {

    private @NonNull ReactiveMultiIdentityProviderAuthenticationResolver resolver;

    @Override
    public void customize(ServerHttpSecurity.OAuth2ResourceServerSpec oAuth2ResourceServerSpec) {
        oAuth2ResourceServerSpec.authenticationManagerResolver(resolver);
    }
}

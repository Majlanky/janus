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

package com.groocraft.janus.configuration;

import com.groocraft.janus.customizer.WithMultiIdPsCustomizer;
import com.groocraft.janus.security.IdentityProviders;
import com.groocraft.janus.security.MultiIdentityProviderAuthenticationResolver;

import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

/**
 * Injects all Janus beans to the context.
 *
 * @author Majlanky
 */
@Configuration(
    proxyBeanMethods = false
)
@AutoConfigureBefore({SecurityAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class})
@EnableConfigurationProperties({OAuth2ResourceServerProperties.class})
@ConditionalOnClass({BearerTokenAuthenticationToken.class})
@ConditionalOnWebApplication(
    type = ConditionalOnWebApplication.Type.SERVLET
)
@Import({MultiIdentityProviderAuthenticationResolver.class, IdentityProviders.class, WithMultiIdPsCustomizer.class})
public class JanusAutoConfiguration {
}

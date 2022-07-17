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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.source.InvalidConfigurationPropertyValueException;
import org.springframework.lang.NonNull;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import lombok.RequiredArgsConstructor;

/**
 * Mapping class for configuration of known IdPs.
 *
 * @author Majlanky
 */
@ConfigurationProperties(prefix = IdentityProviders.PREFIX)
@RequiredArgsConstructor
public class IdentityProviders implements InitializingBean {

    public static final String PREFIX = "spring.security.oauth2";

    private final Map<String, IdentityProvider> resourceserver;
    private final Map<String, IdentityProvider> knownIdPs = new HashMap<>();

    /**
     * Method for Spring configuration initialization.
     *
     * @return map where known IdPs are mapped.
     */
    @NonNull
    public Map<String, IdentityProvider> getResourceserver() {
        return resourceserver;
    }

    /**
     * @return map of known IdPs keyed by an issuer uri.
     */
    @NonNull
    Map<String, IdentityProvider> getKnownIdPs() {
        return knownIdPs;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void afterPropertiesSet() {
        validateAndReindex();
    }

    public void validateAndReindex() {
        for (Map.Entry<String, IdentityProvider> configuration : resourceserver.entrySet()) {
            if (configuration.getValue().getJwkSetUri() != null) {
                try {
                    new URL(configuration.getValue().getJwkSetUri());
                } catch (MalformedURLException e) {
                    throw new InvalidConfigurationPropertyValueException(
                        PREFIX + "." + "resourceserver." + configuration.getKey() + ".jwk-set-uri", configuration.getValue().getJwkSetUri(),
                        "Malformed URL");
                }
            }
            knownIdPs.put(configuration.getValue().getIssuerUri(), configuration.getValue());
            configuration.getValue().setId(configuration.getKey());
        }
    }

}

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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * {@link WebSecurityConfigurerAdapter} extension for fluent coding. It adds the {@link #withMultiIdPs()} method that
 * can be used as parameter for
 * {@link org.springframework.security.config.annotation.web.builders.HttpSecurity#oauth2ResourceServer(Customizer)} call which causes
 * adding support for multi IdPs.
 *
 * @author Majlanky
 * @deprecated Approach of {@link WebSecurityConfigurerAdapter} can be deprecated in your application. If so,
 * use {@link org.springframework.security.web.SecurityFilterChain} with {@link WithMultiIdPsCustomizer} instead
 */
@Deprecated
public abstract class JanusWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {

    private WithMultiIdPsCustomizer withMultiIdPsCustomizer;

    protected JanusWebSecurityConfigurerAdapter() {
        super();
    }

    protected JanusWebSecurityConfigurerAdapter(boolean disableDefaults) {
        super(disableDefaults);
    }

    @Autowired
    public void setWithMultiIdPsCustomizer(WithMultiIdPsCustomizer withMultiIdPsCustomizer) {
        this.withMultiIdPsCustomizer = withMultiIdPsCustomizer;
    }

    /**
     * @return customizer that adds support for multi identity providers for oauth2 resource server.
     */
    protected WithMultiIdPsCustomizer withMultiIdPs() {
        return withMultiIdPsCustomizer;
    }

}

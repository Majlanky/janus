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

import com.groocraft.janus.customizer.ReactiveWithMultiIdPsCustomizer;
import com.groocraft.janus.security.IdentityProviders;
import com.groocraft.janus.security.ReactiveMultiIdentityProviderAuthenticationResolver;

import org.springframework.context.annotation.Import;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Non-parametric annotation to turn on reactive Janus manually when auto-configuration is off, or for test purposes.
 *
 * @author Majlanky
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@Import({ReactiveMultiIdentityProviderAuthenticationResolver.class, IdentityProviders.class, ReactiveWithMultiIdPsCustomizer.class})
public @interface EnableReactiveJanus {
}

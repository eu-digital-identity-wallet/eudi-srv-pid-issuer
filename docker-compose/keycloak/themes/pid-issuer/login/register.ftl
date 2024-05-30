<#import "template.ftl" as layout>
<#import "register-commons.ftl" as registerCommons>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('firstName','lastName','user.attributes.gender','user.attributes.birthdate','user.attributes.age_over_18','user.attributes.picture','user.attributes.street','user.attributes.locality','user.attributes.region','user.attributes.postal_code','user.attributes.country','user.attributes.formatted','username','email','password','password-confirm','termsAccepted'); section>
    <#if section = "header">
        ${msg("registerTitle")}
    <#elseif section = "form">
        <form id="kc-register-form" class="${properties.kcFormClass!}" action="${url.registrationAction}" method="post">
            <h2>${msg("profile")}</h2>
            <!-- given_name -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="firstName" class="${properties.kcLabelClass!}">${msg("firstName")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="firstName" class="${properties.kcInputClass!}" name="firstName"
                           value="${(register.formData.firstName!'')}"
                           aria-invalid="<#if messagesPerField.existsError('firstName')>true</#if>"
                    />

                    <#if messagesPerField.existsError('firstName')>
                        <span id="input-error-firstname" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('firstName'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /given_name -->

            <!-- family_name -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="lastName" class="${properties.kcLabelClass!}">${msg("lastName")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="lastName" class="${properties.kcInputClass!}" name="lastName"
                           value="${(register.formData.lastName!'')}"
                           aria-invalid="<#if messagesPerField.existsError('lastName')>true</#if>"
                    />

                    <#if messagesPerField.existsError('lastName')>
                        <span id="input-error-lastname" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('lastName'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /family_name -->

            <!-- gender -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.gender" class="${properties.kcLabelClass!}">${msg("gender")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <select id="user.attributes.gender" class="${properties.kcInputClass!}" name="user.attributes.gender"
                            value="${(register.formData['user.attributes.gender']!'')}"
                            aria-invalid="<#if messagesPerField.existsError('user.attributes.gender')>true</#if>">
                        <option value="0" aria-label="${msg("gender_not_known")}">${msg("gender_not_known")}</option>
                        <option value="1" aria-label="${msg("gender_male")}">${msg("gender_male")}</option>
                        <option value="2" aria-label="${msg("gender_female")}">${msg("gender_female")}</option>
                        <option value="3" aria-label="${msg("gender_not_applicable")}">${msg("gender_not_applicable")}</option>
                    </select>
                    <#if messagesPerField.existsError('user.attributes.gender')>
                        <span id="input-error-user.attributes.gender" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.gender'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /gender -->

            <!-- birthdate -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.birthdate" class="${properties.kcLabelClass!}">${msg("birthdate")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="date" id="user.attributes.birthdate" class="${properties.kcInputClass!}" name="user.attributes.birthdate"
                           value="${(register.formData['user.attributes.birthdate']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.birthdate')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.birthdate')>
                        <span id="input-error-user.attributes.birthdate" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.birthdate'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /birthdate -->

            <!-- age_over_18 -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.age_over_18" class="${properties.kcLabelClass!}">${msg("age_over_18")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <select id="user.attributes.age_over_18" class="${properties.kcInputClass!}" name="user.attributes.age_over_18"
                            value="${(register.formData['user.attributes.age_over_18']!'')}"
                            aria-invalid="<#if messagesPerField.existsError('user.attributes.age_over_18')>true</#if>">
                        <option value="true" aria-label="${msg("age_over_18_yes")}">${msg("age_over_18_yes")}</option>
                        <option value="false" aria-label="${msg("age_over_18_no")}">${msg("age_over_18_no")}</option>
                    </select>
                    <#if messagesPerField.existsError('user.attributes.age_over_18')>
                        <span id="input-error-user.attributes.age_over_18" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.age_over_18'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /age_over_18 -->

            <!-- picture -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.picture" class="${properties.kcLabelClass!}">${msg("picture")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="user.attributes.picture" class="${properties.kcInputClass!}" name="user.attributes.picture"
                           value="${(register.formData['user.attributes.picture']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.picture')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.picture')>
                        <span id="input-error-user.attributes.picture" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.picture'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /picture -->

            <h3>${msg("address")}</h3>

            <!-- street -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.street" class="${properties.kcLabelClass!}">${msg("street")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="user.attributes.street" class="${properties.kcInputClass!}" name="user.attributes.street"
                           value="${(register.formData['user.attributes.street']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.street')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.street')>
                        <span id="input-error-user.attributes.street" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.street'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /street -->

            <!-- locality -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.locality" class="${properties.kcLabelClass!}">${msg("locality")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="user.attributes.locality" class="${properties.kcInputClass!}" name="user.attributes.locality"
                           value="${(register.formData['user.attributes.locality']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.locality')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.locality')>
                        <span id="input-error-user.attributes.locality" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.locality'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /locality -->

            <!-- region -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.region" class="${properties.kcLabelClass!}">${msg("region")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="user.attributes.region" class="${properties.kcInputClass!}" name="user.attributes.region"
                           value="${(register.formData['user.attributes.region']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.region')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.region')>
                        <span id="input-error-user.attributes.region" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.region'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /region -->

            <!-- postal_code -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.postal_code" class="${properties.kcLabelClass!}">${msg("postal_code")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="user.attributes.postal_code" class="${properties.kcInputClass!}" name="user.attributes.postal_code"
                           value="${(register.formData['user.attributes.postal_code']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.postal_code')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.postal_code')>
                        <span id="input-error-user.attributes.postal_code" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.postal_code'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /postal_code -->

            <!-- country -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.country" class="${properties.kcLabelClass!}">${msg("country")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="user.attributes.country" class="${properties.kcInputClass!}" name="user.attributes.country"
                           value="${(register.formData['user.attributes.country']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.country')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.country')>
                        <span id="input-error-user.attributes.country" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.country'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /country -->

            <!-- formatted -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="user.attributes.formatted" class="${properties.kcLabelClass!}">${msg("formatted")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="text" id="user.attributes.formatted" class="${properties.kcInputClass!}" name="user.attributes.formatted"
                           value="${(register.formData['user.attributes.formatted']!'')}"
                           aria-invalid="<#if messagesPerField.existsError('user.attributes.formatted')>true</#if>"
                    />

                    <#if messagesPerField.existsError('user.attributes.formatted')>
                        <span id="input-error-user.attributes.formatted" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('user.attributes.formatted'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /formatted -->

            <h2>${msg("credential_configuration_ids")}</h2>
            <!-- username -->
            <#if !realm.registrationEmailAsUsername>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcLabelWrapperClass!}">
                        <label for="username" class="${properties.kcLabelClass!}">${msg("username")}</label>
                    </div>
                    <div class="${properties.kcInputWrapperClass!}">
                        <input type="text" id="username" class="${properties.kcInputClass!}" name="username"
                               value="${(register.formData.username!'')}" autocomplete="username"
                               aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                        />

                        <#if messagesPerField.existsError('username')>
                            <span id="input-error-username" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('username'))?no_esc}
                            </span>
                        </#if>
                    </div>
                </div>
            </#if>
            <!-- /username -->

            <!-- email -->
            <div class="${properties.kcFormGroupClass!}">
                <div class="${properties.kcLabelWrapperClass!}">
                    <label for="email" class="${properties.kcLabelClass!}">${msg("email")}</label>
                </div>
                <div class="${properties.kcInputWrapperClass!}">
                    <input type="email" id="email" class="${properties.kcInputClass!}" name="email"
                           value="${(register.formData.email!'')}"
                           aria-invalid="<#if messagesPerField.existsError('email')>true</#if>"
                    />

                    <#if messagesPerField.existsError('email')>
                        <span id="input-error-email" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                            ${kcSanitize(messagesPerField.get('email'))?no_esc}
                        </span>
                    </#if>
                </div>
            </div>
            <!-- /email -->

            <!-- password -->
            <#if passwordRequired??>
                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcLabelWrapperClass!}">
                        <label for="password" class="${properties.kcLabelClass!}">${msg("password")}</label>
                    </div>
                    <div class="${properties.kcInputWrapperClass!}">
                        <div class="${properties.kcInputGroup!}">
                            <input type="password" id="password" class="${properties.kcInputClass!}" name="password"
                                   autocomplete="new-password"
                                   aria-invalid="<#if messagesPerField.existsError('password','password-confirm')>true</#if>"
                            />
                            <button class="pf-c-button pf-m-control" type="button" aria-label="${msg('showPassword')}"
                                    aria-controls="password"  data-password-toggle
                                    data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
                                <i class="fa fa-eye" aria-hidden="true"></i>
                            </button>
                        </div>


                        <#if messagesPerField.existsError('password')>
                            <span id="input-error-password" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('password'))?no_esc}
                            </span>
                        </#if>
                    </div>
                </div>

                <div class="${properties.kcFormGroupClass!}">
                    <div class="${properties.kcLabelWrapperClass!}">
                        <label for="password-confirm"
                               class="${properties.kcLabelClass!}">${msg("passwordConfirm")}</label>
                    </div>
                    <div class="${properties.kcInputWrapperClass!}">
                        <div class="${properties.kcInputGroup!}">
                            <input type="password" id="password-confirm" class="${properties.kcInputClass!}"
                                   name="password-confirm"
                                   aria-invalid="<#if messagesPerField.existsError('password-confirm')>true</#if>"
                            />
                            <button class="pf-c-button pf-m-control" type="button" aria-label="${msg('showPassword')}"
                                    aria-controls="password-confirm"  data-password-toggle
                                    data-label-show="${msg('showPassword')}" data-label-hide="${msg('hidePassword')}">
                                <i class="fa fa-eye" aria-hidden="true"></i>
                            </button>
                        </div>

                        <#if messagesPerField.existsError('password-confirm')>
                            <span id="input-error-password-confirm" class="${properties.kcInputErrorMessageClass!}" aria-live="polite">
                                ${kcSanitize(messagesPerField.get('password-confirm'))?no_esc}
                            </span>
                        </#if>
                    </div>
                </div>
            </#if>
            <!-- /password -->

            <!-- Terms and Conditions -->
            <@registerCommons.termsAcceptance/>
            <!-- /Terms and Conditions -->

            <!-- Captcha -->
            <#if recaptchaRequired??>
                <div class="form-group">
                    <div class="${properties.kcInputWrapperClass!}">
                        <div class="g-recaptcha" data-size="compact" data-sitekey="${recaptchaSiteKey}"></div>
                    </div>
                </div>
            </#if>
            <!-- /Captcha -->

            <!-- Back to Login -->
            <div class="${properties.kcFormGroupClass!}">
                <div id="kc-form-options" class="${properties.kcFormOptionsClass!}">
                    <div class="${properties.kcFormOptionsWrapperClass!}">
                        <span><a href="${url.loginUrl}">${kcSanitize(msg("backToLogin"))?no_esc}</a></span>
                    </div>
                </div>

                <div id="kc-form-buttons" class="${properties.kcFormButtonsClass!}">
                    <input class="${properties.kcButtonClass!} ${properties.kcButtonPrimaryClass!} ${properties.kcButtonBlockClass!} ${properties.kcButtonLargeClass!}" type="submit" value="${msg("doRegister")}"/>
                </div>
            </div>
            <!-- /Back to Login -->
        </form>
        <script type="module" src="${url.resourcesPath}/js/passwordVisibility.js"></script>
    </#if>
</@layout.registrationLayout>

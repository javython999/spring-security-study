package com.errday.springsecuritystudy.annotation;

import org.springframework.security.access.prepost.PreAuthorize;

import java.lang.annotation.*;

import static java.lang.annotation.ElementType.*;
import static java.lang.annotation.RetentionPolicy.*;

@Documented
@Retention(RUNTIME)
@Target({TYPE, METHOD})
@PreAuthorize("hasRole('ADMIN')")
public @interface IsAdmin {
}

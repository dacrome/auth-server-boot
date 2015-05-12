/*
 * Copyright (C) 2013 tarent AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.osiam.auth_server.exception;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.handler.SimpleMappingExceptionResolver;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@ControllerAdvice
public class OsiamExceptionHandler extends SimpleMappingExceptionResolver {

    private static final Logger LOGGER = Logger.getLogger(OsiamExceptionHandler.class.getName());

    @ExceptionHandler(value = { Exception.class })
    protected ModelAndView handleConflict(HttpServletRequest request, Exception e) {
        LOGGER.log(Level.WARNING, "An exception occurred", e);
        return new ModelAndView("oauth_error");
    }
    
    @ExceptionHandler(value = { ResourceNotFoundException.class })
    @ResponseStatus(HttpStatus.NOT_FOUND)
    protected @ResponseBody JsonErrorResult handleResourceNotFound(HttpServletRequest request, HttpServletResponse response, ResourceNotFoundException e) {
        LOGGER.log(Level.WARNING, "A ResourceNotFoundException occurred", e);
        JsonErrorResult error = new JsonErrorResult(HttpStatus.NOT_FOUND.name(), e.getMessage());
        return error;
    }
    
    @JsonSerialize(include = JsonSerialize.Inclusion.NON_EMPTY)
    static class JsonErrorResult {
        private String error_code; // NOSONAR - needed pattern due to json serializing
        private String description;

        public JsonErrorResult(String name, String message) {
            error_code = name;
            description = message;
        }

        public String getError_code() { // NOSONAR - needed pattern due to json serializing
            return error_code;
        }

        public String getDescription() {
            return description;
        }
    }
}

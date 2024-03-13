// Copyright 2017 The go-simplechain Authors
// This file is part of the go-simplechain library.
//
// The go-simplechain library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-simplechain library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-simplechain library. If not, see <http://www.gnu.org/licenses/>.

package rpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTPSErrorResponseWithDelete(t *testing.T) {
	testHTTPErrorResponse(t, http.MethodDelete, contentType, "", http.StatusMethodNotAllowed)
}

func TestHTTPSErrorResponseWithPut(t *testing.T) {
	testHTTPErrorResponse(t, http.MethodPut, contentType, "", http.StatusMethodNotAllowed)
}

func TestHTTPSErrorResponseWithMaxContentLength(t *testing.T) {
	body := make([]rune, maxRequestContentLength+1)
	testHTTPErrorResponse(t,
		http.MethodPost, contentType, string(body), http.StatusRequestEntityTooLarge)
}

func TestHTTPSErrorResponseWithEmptyContentType(t *testing.T) {
	testHTTPErrorResponse(t, http.MethodPost, "", "", http.StatusUnsupportedMediaType)
}

func TestHTTPSErrorResponseWithValidRequest(t *testing.T) {
	testHTTPErrorResponse(t, http.MethodPost, contentType, "", 0)
}

func testHTTPSErrorResponse(t *testing.T, method, contentType, body string, expected int) {
	request := httptest.NewRequest(method, "http://url.com", strings.NewReader(body))
	request.Header.Set("content-type", contentType)
	if code, _ := validateRequest(request); code != expected {
		t.Fatalf("response code should be %d not %d", expected, code)
	}
}

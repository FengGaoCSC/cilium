// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/http/custom_response/redirect_policy/v3/redirect_policy.proto

package redirect_policyv3

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on RedirectPolicy with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *RedirectPolicy) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on RedirectPolicy with the rules defined
// in the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in RedirectPolicyMultiError,
// or nil if none found.
func (m *RedirectPolicy) ValidateAll() error {
	return m.validate(true)
}

func (m *RedirectPolicy) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if wrapper := m.GetStatusCode(); wrapper != nil {

		if val := wrapper.GetValue(); val < 100 || val > 999 {
			err := RedirectPolicyValidationError{
				field:  "StatusCode",
				reason: "value must be inside range [100, 999]",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if len(m.GetResponseHeadersToAdd()) > 1000 {
		err := RedirectPolicyValidationError{
			field:  "ResponseHeadersToAdd",
			reason: "value must contain no more than 1000 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetResponseHeadersToAdd() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, RedirectPolicyValidationError{
						field:  fmt.Sprintf("ResponseHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, RedirectPolicyValidationError{
						field:  fmt.Sprintf("ResponseHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RedirectPolicyValidationError{
					field:  fmt.Sprintf("ResponseHeadersToAdd[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(m.GetRequestHeadersToAdd()) > 1000 {
		err := RedirectPolicyValidationError{
			field:  "RequestHeadersToAdd",
			reason: "value must contain no more than 1000 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetRequestHeadersToAdd() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, RedirectPolicyValidationError{
						field:  fmt.Sprintf("RequestHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, RedirectPolicyValidationError{
						field:  fmt.Sprintf("RequestHeadersToAdd[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RedirectPolicyValidationError{
					field:  fmt.Sprintf("RequestHeadersToAdd[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if all {
		switch v := interface{}(m.GetModifyRequestHeadersAction()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, RedirectPolicyValidationError{
					field:  "ModifyRequestHeadersAction",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, RedirectPolicyValidationError{
					field:  "ModifyRequestHeadersAction",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetModifyRequestHeadersAction()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return RedirectPolicyValidationError{
				field:  "ModifyRequestHeadersAction",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	switch m.RedirectActionSpecifier.(type) {

	case *RedirectPolicy_Uri:

		if utf8.RuneCountInString(m.GetUri()) < 1 {
			err := RedirectPolicyValidationError{
				field:  "Uri",
				reason: "value length must be at least 1 runes",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	case *RedirectPolicy_RedirectAction:

		if all {
			switch v := interface{}(m.GetRedirectAction()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, RedirectPolicyValidationError{
						field:  "RedirectAction",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, RedirectPolicyValidationError{
						field:  "RedirectAction",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetRedirectAction()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RedirectPolicyValidationError{
					field:  "RedirectAction",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		err := RedirectPolicyValidationError{
			field:  "RedirectActionSpecifier",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)

	}

	if len(errors) > 0 {
		return RedirectPolicyMultiError(errors)
	}
	return nil
}

// RedirectPolicyMultiError is an error wrapping multiple validation errors
// returned by RedirectPolicy.ValidateAll() if the designated constraints
// aren't met.
type RedirectPolicyMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m RedirectPolicyMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m RedirectPolicyMultiError) AllErrors() []error { return m }

// RedirectPolicyValidationError is the validation error returned by
// RedirectPolicy.Validate if the designated constraints aren't met.
type RedirectPolicyValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RedirectPolicyValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RedirectPolicyValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RedirectPolicyValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RedirectPolicyValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RedirectPolicyValidationError) ErrorName() string { return "RedirectPolicyValidationError" }

// Error satisfies the builtin error interface
func (e RedirectPolicyValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRedirectPolicy.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RedirectPolicyValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RedirectPolicyValidationError{}

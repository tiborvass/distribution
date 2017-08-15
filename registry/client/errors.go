package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/docker/distribution/registry/api/errcode"
	"github.com/docker/distribution/registry/client/auth/challenge"
	"github.com/opencontainers/go-digest"
)

// ErrNoErrorsInBody is returned when an HTTP response body parses to an empty
// errcode.Errors slice.
var ErrNoErrorsInBody = errors.New("no error details found in HTTP response body")

// UnexpectedHTTPStatusError is returned when an unexpected HTTP status is
// returned when making a registry api call.
type UnexpectedHTTPStatusError struct {
	Status string
}

func (e *UnexpectedHTTPStatusError) Error() string {
	return fmt.Sprintf("received unexpected HTTP status: %s", e.Status)
}

// UnexpectedHTTPResponseError is returned when an expected HTTP status code
// is returned, but the content was unexpected and failed to be parsed.
type UnexpectedHTTPResponseError struct {
	ParseErr   error
	StatusCode int
	Response   []byte
}

func (e *UnexpectedHTTPResponseError) Error() string {
	return fmt.Sprintf("error parsing HTTP %d response body: %s: %q", e.StatusCode, e.ParseErr.Error(), string(e.Response))
}

func parseHTTPErrorResponse(statusCode int, r io.Reader) error {
	var errors errcode.Errors
	body, err := ioutil.ReadAll(r)
	if err != nil {
		return err
	}

	// For backward compatibility, handle irregularly formatted
	// messages that contain a "details" field.
	var detailsErr struct {
		Details string `json:"details"`
	}
	err = json.Unmarshal(body, &detailsErr)
	if err == nil && detailsErr.Details != "" {
		switch statusCode {
		case http.StatusUnauthorized:
			return errcode.ErrorCodeUnauthorized.WithMessage(detailsErr.Details)
		case http.StatusTooManyRequests:
			return errcode.ErrorCodeTooManyRequests.WithMessage(detailsErr.Details)
		default:
			return errcode.ErrorCodeUnknown.WithMessage(detailsErr.Details)
		}
	}

	if err := json.Unmarshal(body, &errors); err != nil {
		return &UnexpectedHTTPResponseError{
			ParseErr:   err,
			StatusCode: statusCode,
			Response:   body,
		}
	}

	if len(errors) == 0 {
		// If there was no error specified in the body, return
		// UnexpectedHTTPResponseError.
		return &UnexpectedHTTPResponseError{
			ParseErr:   ErrNoErrorsInBody,
			StatusCode: statusCode,
			Response:   body,
		}
	}

	return errors
}

func makeErrorList(err error) []error {
	if errL, ok := err.(errcode.Errors); ok {
		return []error(errL)
	}
	return []error{err}
}

func mergeErrors(err1, err2 error) error {
	return errcode.Errors(append(makeErrorList(err1), makeErrorList(err2)...))
}

// HandleErrorResponse returns error parsed from HTTP response for an
// unsuccessful HTTP response code (in the range 400 - 499 inclusive). An
// UnexpectedHTTPStatusError returned for response code outside of expected
// range.
func HandleErrorResponse(resp *http.Response) error {
	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		// Check for OAuth errors within the `WWW-Authenticate` header first
		// See https://tools.ietf.org/html/rfc6750#section-3
		for _, c := range challenge.ResponseChallenges(resp) {
			if c.Scheme == "bearer" {
				var err errcode.Error
				// codes defined at https://tools.ietf.org/html/rfc6750#section-3.1
				switch c.Parameters["error"] {
				case "invalid_token":
					err.Code = errcode.ErrorCodeUnauthorized
				case "insufficient_scope":
					err.Code = errcode.ErrorCodeDenied
				default:
					continue
				}
				if description := c.Parameters["error_description"]; description != "" {
					err.Message = description
				} else {
					err.Message = err.Code.Message()
				}

				return mergeErrors(err, parseHTTPErrorResponse(resp.StatusCode, resp.Body))
			}
		}
		err := parseHTTPErrorResponse(resp.StatusCode, resp.Body)
		if uErr, ok := err.(*UnexpectedHTTPResponseError); ok && resp.StatusCode == 401 {
			return errcode.ErrorCodeUnauthorized.WithDetail(uErr.Response)
		}
		return err
	}
	return &UnexpectedHTTPStatusError{Status: resp.Status}
}

// SuccessStatus returns true if the argument is a successful HTTP response
// code (in the range 200 - 399 inclusive).
func SuccessStatus(status int) bool {
	return status >= 200 && status <= 399
}

// ErrAccessDenied is returned when an access to a requested resource is
// denied.
var ErrAccessDenied = errors.New("access denied")

// ErrManifestNotModified is returned when a conditional manifest GetByTag
// returns nil due to the client indicating it has the latest version
var ErrManifestNotModified = errors.New("manifest not modified")

// ErrUnsupported is returned when an unimplemented or unsupported action is
// performed
var ErrUnsupported = errors.New("operation unsupported")

// ErrTagUnknown is returned if the given tag is not known by the tag service
type ErrTagUnknown struct {
	Tag string
}

func (err ErrTagUnknown) Error() string {
	return fmt.Sprintf("unknown tag=%s", err.Tag)
}

// ErrRepositoryUnknown is returned if the named repository is not known by
// the registry.
type ErrRepositoryUnknown struct {
	Name string
}

func (err ErrRepositoryUnknown) Error() string {
	return fmt.Sprintf("unknown repository name=%s", err.Name)
}

// ErrRepositoryNameInvalid should be used to denote an invalid repository
// name. Reason may set, indicating the cause of invalidity.
type ErrRepositoryNameInvalid struct {
	Name   string
	Reason error
}

func (err ErrRepositoryNameInvalid) Error() string {
	return fmt.Sprintf("repository name %q invalid: %v", err.Name, err.Reason)
}

// ErrManifestUnknown is returned if the manifest is not known by the
// registry.
type ErrManifestUnknown struct {
	Name string
	Tag  string
}

func (err ErrManifestUnknown) Error() string {
	return fmt.Sprintf("unknown manifest name=%s tag=%s", err.Name, err.Tag)
}

// ErrManifestUnknownRevision is returned when a manifest cannot be found by
// revision within a repository.
type ErrManifestUnknownRevision struct {
	Name     string
	Revision digest.Digest
}

func (err ErrManifestUnknownRevision) Error() string {
	return fmt.Sprintf("unknown manifest name=%s revision=%s", err.Name, err.Revision)
}

// ErrManifestUnverified is returned when the registry is unable to verify
// the manifest.
type ErrManifestUnverified struct{}

func (ErrManifestUnverified) Error() string {
	return "unverified manifest"
}

// ErrManifestVerification provides a type to collect errors encountered
// during manifest verification. Currently, it accepts errors of all types,
// but it may be narrowed to those involving manifest verification.
type ErrManifestVerification []error

func (errs ErrManifestVerification) Error() string {
	var parts []string
	for _, err := range errs {
		parts = append(parts, err.Error())
	}

	return fmt.Sprintf("errors verifying manifest: %v", strings.Join(parts, ","))
}

// ErrManifestBlobUnknown returned when a referenced blob cannot be found.
type ErrManifestBlobUnknown struct {
	Digest digest.Digest
}

func (err ErrManifestBlobUnknown) Error() string {
	return fmt.Sprintf("unknown blob %v on manifest", err.Digest)
}

// ErrManifestNameInvalid should be used to denote an invalid manifest
// name. Reason may set, indicating the cause of invalidity.
type ErrManifestNameInvalid struct {
	Name   string
	Reason error
}

func (err ErrManifestNameInvalid) Error() string {
	return fmt.Sprintf("manifest name %q invalid: %v", err.Name, err.Reason)
}

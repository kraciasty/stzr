// Package stzr provides a simple sanitization policy wrapper for tag-based
// sanitization of structs containing user input.
//
// This package wraps bluemonday policies to enable automatic HTML sanitization
// of struct fields based on struct tags. It supports recursive sanitization
// of nested structs, slices, maps, generics and pointers.
//
// The default sanitizer instance comes with "strict" and "ugc" bluemonday
// policies and can be configured further.
package stzr

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/microcosm-cc/bluemonday"
)

const reservedPolicyPanicMsg = `policy name "-" is reserved for skipping sanitization`

// ErrPolicyNotFound is returned when a requested policy is not found.
var ErrPolicyNotFound = errors.New("sanitization policy not found")

var defaultSanitizer atomic.Pointer[Sanitizer]

func init() {
	defaultSanitizer.Store(New(
		WithPolicy("strict", bluemonday.StrictPolicy()),
		WithPolicy("ugc", bluemonday.UGCPolicy()),
	))
}

// Default returns the default Sanitizer. By default, it includes "ugc" and
// "strict" policies that match the bluemonday UGC and Strict policies, but
// the global instance may be modified by calling SetDefault.
func Default() *Sanitizer { return defaultSanitizer.Load() }

// SetDefault sets the default Sanitizer used by the package-level functions.
func SetDefault(s *Sanitizer) {
	defaultSanitizer.Store(s)
}

// SanitizeString applies sanitization using the default sanitizer.
func SanitizeString(policy string, input string) (string, error) {
	return Default().SanitizeString(policy, input)
}

// SanitizeStruct applies sanitization using the default sanitizer instance.
func SanitizeStruct(v any) error {
	return Default().SanitizeStruct(v)
}

// Policy is a sanitization policy like [bluemonday.Policy].
type Policy interface {
	Sanitize(s string) string
}

// PolicyFunc is a function type that implements the Policy interface.
type PolicyFunc (func(s string) string)

// Sanitize implements the Policy interface for PolicyFunc.
func (f PolicyFunc) Sanitize(s string) string {
	return f(s)
}

// Sanitizer provides configurable HTML sanitization based on struct tags.
type Sanitizer struct {
	mu       sync.RWMutex
	tagKey   string
	policies map[string]Policy
}

// Opt defines a functional option type for configuring the Sanitizer.
type Opt func(*Sanitizer)

// New creates a new Sanitizer with no default policies.
// Use functional options to configure the sanitizer's behavior.
func New(opts ...Opt) *Sanitizer {
	s := &Sanitizer{
		tagKey:   "sanitize",
		policies: make(map[string]Policy),
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// WithPolicy adds a custom sanitization policy to the Sanitizer.
// The name "-" is reserved and cannot be used as a policy name.
func WithPolicy(name string, policy Policy) Opt {
	return func(s *Sanitizer) {
		if name == "-" {
			panic(reservedPolicyPanicMsg)
		}

		s.policies[name] = policy
	}
}

// WithTagKey sets the tag key used for sanitization policies.
func WithTagKey(key string) Opt {
	return func(s *Sanitizer) {
		s.tagKey = key
	}
}

// Add allows adding custom sanitizers to this instance.
// The name "-" is reserved and cannot be used as a policy name.
func (s *Sanitizer) Add(name string, policy *bluemonday.Policy) {
	if name == "-" {
		panic(reservedPolicyPanicMsg)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[name] = policy
}

// Remove a sanitizer policy by name.
func (s *Sanitizer) Remove(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.policies, name)
}

// SanitizeString applies sanitization based on the given policy name.
func (s *Sanitizer) SanitizeString(policy string, input string) (string, error) {
	s.mu.RLock()
	p, ok := s.policies[policy]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("policy %q: %w", policy, ErrPolicyNotFound)
	}

	return p.Sanitize(input), nil
}

// SanitizeStruct applies sanitization based on struct tags.
func (s *Sanitizer) SanitizeStruct(v any) error {
	if v == nil {
		return nil
	}

	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Ptr || rv.IsNil() {
		return fmt.Errorf("expected pointer to struct, got %T", v)
	}

	elem := rv.Elem()
	if !elem.IsValid() || elem.IsZero() {
		return nil
	}

	return s.sanitizeRecursive(elem)
}

func (s *Sanitizer) sanitizeRecursive(rv reflect.Value) error {
	if !rv.IsValid() || rv.IsZero() {
		return nil
	}

	switch rv.Kind() {
	case reflect.Struct:
		return s.sanitizeStruct(rv)
	case reflect.Ptr:
		return s.sanitizePointer(rv)
	case reflect.Slice, reflect.Array:
		return s.sanitizeSliceOrArray(rv)
	case reflect.Map:
		return s.sanitizeMap(rv)
	case reflect.Interface:
		return s.sanitizeInterface(rv)
	}

	return nil
}

// sanitizeStruct processes struct fields and applies sanitization based on tags
func (s *Sanitizer) sanitizeStruct(rv reflect.Value) error {
	rt := rv.Type()
	for i := 0; i < rv.NumField(); i++ {
		field := rv.Field(i)
		sf := rt.Field(i)

		if !field.CanSet() {
			continue
		}

		if err := s.sanitizeField(field, sf); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeField handles individual field sanitization
func (s *Sanitizer) sanitizeField(field reflect.Value, sf reflect.StructField) error {
	tag := sf.Tag.Get(s.tagKey)
	if tag == "-" {
		return nil
	}

	if tag != "" && field.Kind() == reflect.String {
		return s.applySanitizationPolicy(field, tag)
	}

	// For non-string fields, always recurse to find tagged fields inside
	// This allows sanitization of nested structs, slices, maps, etc.
	if field.Kind() != reflect.String {
		return s.sanitizeRecursive(field)
	}

	return nil
}

// applySanitizationPolicy applies the specified policy to a string field
func (s *Sanitizer) applySanitizationPolicy(field reflect.Value, policyName string) error {
	policy, err := s.getPolicy(policyName)
	if err != nil {
		return err
	}

	sanitized := policy.Sanitize(field.String())
	field.SetString(sanitized)
	return nil
}

// getPolicy retrieves a policy by name with proper locking
func (s *Sanitizer) getPolicy(name string) (Policy, error) {
	s.mu.RLock()
	policy, ok := s.policies[name]
	s.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("policy %q: %w", name, ErrPolicyNotFound)
	}

	return policy, nil
}

// sanitizePointer handles pointer sanitization
func (s *Sanitizer) sanitizePointer(rv reflect.Value) error {
	if rv.IsNil() {
		return nil
	}
	return s.sanitizeRecursive(rv.Elem())
}

// sanitizeSliceOrArray handles slice and array sanitization
func (s *Sanitizer) sanitizeSliceOrArray(rv reflect.Value) error {
	for i := 0; i < rv.Len(); i++ {
		if err := s.sanitizeRecursive(rv.Index(i)); err != nil {
			return err
		}
	}
	return nil
}

// sanitizeMap handles map sanitization with improved logic
func (s *Sanitizer) sanitizeMap(rv reflect.Value) error {
	for _, key := range rv.MapKeys() {
		val := rv.MapIndex(key)
		if !val.CanInterface() {
			continue
		}

		newVal := reflect.New(val.Type()).Elem()
		newVal.Set(val)
		if err := s.sanitizeRecursive(newVal); err != nil {
			return err
		}

		rv.SetMapIndex(key, newVal)
	}
	return nil
}

// sanitizeInterface handles interface sanitization
func (s *Sanitizer) sanitizeInterface(rv reflect.Value) error {
	if rv.IsNil() {
		return nil
	}
	return s.sanitizeRecursive(reflect.ValueOf(rv.Interface()))
}

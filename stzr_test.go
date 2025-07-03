package stzr_test

import (
	"fmt"
	"testing"

	"github.com/kraciasty/stzr"
	"github.com/microcosm-cc/bluemonday"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ExampleSanitizer_SanitizeStruct() {
	type Character struct {
		Name string `sanitize:"strict"`
		Bio  string `sanitize:"ugc"`
	}

	s := stzr.Default()
	character := &Character{
		Name: `<script>alert('morty')</script>Rick <b>Sanchez</b>`,
		Bio:  `Genius <b>scientist</b> from dimension C-137 <script>alert('wubba lubba dub dub')</script>`,
	}

	fmt.Printf("Before:\n")
	fmt.Printf("Name: %s\n", character.Name)
	fmt.Printf("Bio: %s\n\n", character.Bio)

	_ = s.SanitizeStruct(character)

	fmt.Printf("After:\n")
	fmt.Printf("Name: %s\n", character.Name)
	fmt.Printf("Bio: %s\n", character.Bio)

	// Output:
	// Before:
	// Name: <script>alert('morty')</script>Rick <b>Sanchez</b>
	// Bio: Genius <b>scientist</b> from dimension C-137 <script>alert('wubba lubba dub dub')</script>
	//
	// After:
	// Name: Rick Sanchez
	// Bio: Genius <b>scientist</b> from dimension C-137
}

func ExampleSanitizer_SanitizeString() {
	s := stzr.Default()
	input := `<script>alert('schwifty')</script>Get <b>schwifty</b> in here!`
	strict, _ := s.SanitizeString("strict", input)
	ugc, _ := s.SanitizeString("ugc", input)

	fmt.Printf("Input: %s\n", input)
	fmt.Printf("Strict: %s\n", strict)
	fmt.Printf("UGC: %s\n", ugc)

	// Output:
	// Input: <script>alert('schwifty')</script>Get <b>schwifty</b> in here!
	// Strict: Get schwifty in here!
	// UGC: Get <b>schwifty</b> in here!
}

func ExampleWithPolicy() {
	s := stzr.New(
		stzr.WithPolicy("strict", bluemonday.StrictPolicy()),
		stzr.WithPolicy("ugc", bluemonday.UGCPolicy()),
		stzr.WithPolicy("italics", bluemonday.NewPolicy().AllowElements("i")),
		stzr.WithPolicy("noop", stzr.PolicyFunc(func(s string) string { return s })),
	)

	input := `<script>alert('schwifty')</script>Get <b>schwifty</b> in here!`
	strict, _ := s.SanitizeString("strict", input)
	ugc, _ := s.SanitizeString("ugc", input)
	italics, _ := s.SanitizeString("italics", input)
	noop, _ := s.SanitizeString("noop", input)

	fmt.Printf("Input: %s\n", input)
	fmt.Printf("Strict: %s\n", strict)
	fmt.Printf("UGC: %s\n", ugc)
	fmt.Printf("Italics: %s\n", italics)
	fmt.Printf("Noop: %s\n", noop)

	// Output:
	// Input: <script>alert('schwifty')</script>Get <b>schwifty</b> in here!
	// Strict: Get schwifty in here!
	// UGC: Get <b>schwifty</b> in here!
	// Italics: Get schwifty in here!
	// Noop: <script>alert('schwifty')</script>Get <b>schwifty</b> in here!
}

func TestSanitizer_SanitizeString(t *testing.T) {
	tests := []struct {
		name    string
		policy  string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:   "strict removes all HTML",
			policy: "strict",
			input:  "<script>alert('xss')</script>Hello <b>World</b>",
			want:   "Hello World",
		},
		{
			name:   "ugc allows safe HTML",
			policy: "ugc",
			input:  "<script>alert('xss')</script>Hello <b>World</b>",
			want:   "Hello <b>World</b>",
		},
		{
			name:    "unknown policy error",
			policy:  "unknown",
			input:   "Hello World",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := stzr.Default()
			got, err := s.SanitizeString(tt.policy, tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSanitizer_SanitizeStruct(t *testing.T) {
	tests := []struct {
		name    string
		options []stzr.Opt
		setup   func(*stzr.Sanitizer)
		run     func(*testing.T, *stzr.Sanitizer)
		wantErr bool
	}{
		{
			name: "basic field sanitization",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					StrictField      string `sanitize:"strict"`
					UGCField         string `sanitize:"ugc"`
					UnsanitizedField string
				}{
					StrictField:      "<script>alert('xss')</script>Hello <b>World</b>",
					UGCField:         "<script>alert('xss')</script>Hello <b>World</b>",
					UnsanitizedField: "<script>alert('xss')</script>Hello <b>World</b>",
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Hello World", input.StrictField)
				assert.Equal(t, "Hello <b>World</b>", input.UGCField)
				assert.Equal(t, "<script>alert('xss')</script>Hello <b>World</b>", input.UnsanitizedField)
			},
		},
		{
			name: "custom policy",
			setup: func(s *stzr.Sanitizer) {
				policy := bluemonday.NewPolicy()
				policy.AllowElements("b", "i")
				s.Add("custom", policy)
			},
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					CustomField string `sanitize:"custom"`
				}{
					CustomField: "<script>alert('xss')</script>Hello <b>World</b> <em>test</em>",
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Hello <b>World</b> test", input.CustomField)
			},
		},
		{
			name: "nested pointers",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					NestedPtr *struct {
						Content string `sanitize:"strict"`
					}
				}{
					NestedPtr: &struct {
						Content string `sanitize:"strict"`
					}{
						Content: "<script>alert('xss')</script>Nested Content",
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Nested Content", input.NestedPtr.Content)
			},
		},
		{
			name: "nil pointers",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					NestedPtr *struct {
						Content string `sanitize:"strict"`
					}
				}{
					NestedPtr: nil,
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Nil(t, input.NestedPtr)
			},
		},
		{
			name: "slices",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type item struct {
					Content string `sanitize:"strict"`
				}

				input := struct {
					Items []item
				}{
					Items: []item{
						{Content: "<script>alert('xss')</script>Item 1"},
						{Content: "<script>alert('xss')</script>Item 2"},
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Item 1", input.Items[0].Content)
				assert.Equal(t, "Item 2", input.Items[1].Content)
			},
		},
		{
			name: "maps",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type item struct {
					Content string `sanitize:"strict"`
				}

				input := struct {
					Data map[string]item
				}{
					Data: map[string]item{
						"key1": {Content: "<script>alert('xss')</script>Value 1"},
						"key2": {Content: "<script>alert('xss')</script>Value 2"},
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Value 1", input.Data["key1"].Content)
				assert.Equal(t, "Value 2", input.Data["key2"].Content)
			},
		},
		{
			name: "interfaces",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type concreteStruct struct {
					Content string `sanitize:"strict"`
				}

				input := struct {
					Data any
				}{
					Data: &concreteStruct{
						Content: "<script>alert('xss')</script>Interface Content",
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Interface Content", input.Data.(*concreteStruct).Content)
			},
		},
		{
			name: "nil interface",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Data any
				}{
					Data: nil,
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Nil(t, input.Data)
			},
		},
		{
			name: "nil input",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				require.NoError(t, s.SanitizeStruct(nil))
			},
		},
		{
			name:    "unknown policy error",
			wantErr: true,
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Field string `sanitize:"unknown"`
				}{
					Field: "test",
				}

				err := s.SanitizeStruct(&input)
				assert.Error(t, err)
			},
		},
		{
			name:    "non-pointer error",
			wantErr: true,
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Field string `sanitize:"strict"`
				}{
					Field: "test",
				}

				err := s.SanitizeStruct(input)
				assert.Error(t, err)
			},
		},
		{
			name: "custom tag key",
			options: []stzr.Opt{
				stzr.WithTagKey("clean"),
			},
			setup: func(s *stzr.Sanitizer) {},
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					DefaultTagField string `sanitize:"strict"`
					CustomTagField  string `clean:"strict"`
				}{
					DefaultTagField: "<script>alert('xss')</script>Default",
					CustomTagField:  "<script>alert('xss')</script>Custom",
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)

				assert.Equal(t, "<script>alert('xss')</script>Default", input.DefaultTagField)
				assert.Equal(t, "Custom", input.CustomTagField)
			},
		},
		{
			name:    "policy function",
			options: []stzr.Opt{stzr.WithPolicy("prefix", stzr.PolicyFunc(func(s string) string { return "PREFIX:" + s }))},

			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Field string `sanitize:"prefix"`
				}{
					Field: "test",
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Equal(t, "PREFIX:test", input.Field)
			},
		},
		{
			name:    "remove policy",
			options: []stzr.Opt{stzr.WithPolicy("removeme", bluemonday.UGCPolicy())},
			setup: func(s *stzr.Sanitizer) {
				result, err := s.SanitizeString("removeme", "<b>test</b>")
				require.NoError(t, err)
				assert.Equal(t, "<b>test</b>", result)

				s.Remove("removeme")
			},
			wantErr: true,
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Field string `sanitize:"removeme"`
				}{
					Field: "<b>test</b>",
				}

				err := s.SanitizeStruct(&input)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "policy \"removeme\": sanitization policy not found")
			},
		},
		{
			name: "reserved policy panic with WithPolicy",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				assert.Panics(t, func() {
					stzr.New(stzr.WithPolicy("-", bluemonday.StrictPolicy()))
				})
			},
		},
		{
			name: "reserved policy panic with Add",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				assert.Panics(t, func() {
					s.Add("-", bluemonday.StrictPolicy())
				})
			},
		},
		{
			name:    "nil pointer input",
			wantErr: true,
			run: func(t *testing.T, s *stzr.Sanitizer) {
				var nilPtr *struct {
					Field string `sanitize:"strict"`
				}
				err := s.SanitizeStruct(nilPtr)
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "expected pointer to struct")
			},
		},
		{
			name: "zero value struct",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := &struct {
					Field string `sanitize:"strict"`
				}{}
				err := s.SanitizeStruct(input)
				require.NoError(t, err)
			},
		},
		{
			name: "unexported fields",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := &struct {
					ExportedField   string `sanitize:"strict"`
					unexportedField string `sanitize:"strict"`
				}{
					ExportedField:   "<script>alert('xss')</script>Exported",
					unexportedField: "<script>alert('xss')</script>Unexported",
				}

				err := s.SanitizeStruct(input)
				require.NoError(t, err)
				assert.Equal(t, "Exported", input.ExportedField)
				assert.Equal(t, "<script>alert('xss')</script>Unexported", input.unexportedField)
			},
		},
		{
			name: "arrays",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Items [2]struct {
						Content string `sanitize:"strict"`
					}
				}{
					Items: [2]struct {
						Content string `sanitize:"strict"`
					}{
						{Content: "<script>alert('xss')</script>Item 1"},
						{Content: "<script>alert('xss')</script>Item 2"},
					},
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Equal(t, "Item 1", input.Items[0].Content)
				assert.Equal(t, "Item 2", input.Items[1].Content)
			},
		},
		{
			name: "empty slice",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Items []struct {
						Content string `sanitize:"strict"`
					}
				}{
					Items: []struct {
						Content string `sanitize:"strict"`
					}{},
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Empty(t, input.Items)
			},
		},
		{
			name: "nil slice",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Items []struct {
						Content string `sanitize:"strict"`
					}
				}{
					Items: nil,
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Nil(t, input.Items)
			},
		},
		{
			name: "empty map",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Data map[string]struct {
						Content string `sanitize:"strict"`
					}
				}{
					Data: make(map[string]struct {
						Content string `sanitize:"strict"`
					}),
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Empty(t, input.Data)
			},
		},
		{
			name: "nil map",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					Data map[string]struct {
						Content string `sanitize:"strict"`
					}
				}{
					Data: nil,
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Nil(t, input.Data)
			},
		},
		{
			name: "deeply nested pointers",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type Level3 struct {
					Content string `sanitize:"strict"`
				}
				type Level2 struct {
					Level3Ptr *Level3
				}
				type Level1 struct {
					Level2Ptr *Level2
				}

				input := struct {
					Level1Ptr *Level1
				}{
					Level1Ptr: &Level1{
						Level2Ptr: &Level2{
							Level3Ptr: &Level3{
								Content: "<script>alert('xss')</script>Deep Content",
							},
						},
					},
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Equal(t, "Deep Content", input.Level1Ptr.Level2Ptr.Level3Ptr.Content)
			},
		},
		{
			name: "interface with nested struct",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type NestedStruct struct {
					Content string `sanitize:"strict"`
				}

				interfaceValue := &NestedStruct{
					Content: "<script>alert('xss')</script>Interface Content",
				}

				input := struct {
					Data any
				}{
					Data: interfaceValue,
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)

				nested, ok := input.Data.(*NestedStruct)
				require.True(t, ok)
				assert.Equal(t, "Interface Content", nested.Content)
			},
		},
		{
			name: "various reflect kinds not handled",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					IntField    int
					FloatField  float64
					BoolField   bool
					StringField string `sanitize:"strict"`
				}{
					IntField:    42,
					FloatField:  3.14,
					BoolField:   true,
					StringField: "<script>alert('xss')</script>String",
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)

				assert.Equal(t, 42, input.IntField)
				assert.Equal(t, 3.14, input.FloatField)
				assert.Equal(t, true, input.BoolField)
				assert.Equal(t, "String", input.StringField)
			},
		},
		{
			name: "channel and function fields",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				input := struct {
					ChannelField chan int
					FuncField    func() string
					StringField  string `sanitize:"strict"`
				}{
					ChannelField: make(chan int),
					FuncField:    func() string { return "test" },
					StringField:  "<script>alert('xss')</script>String",
				}

				err := s.SanitizeStruct(&input)
				require.NoError(t, err)

				assert.NotNil(t, input.ChannelField)
				assert.NotNil(t, input.FuncField)
				assert.Equal(t, "String", input.StringField)
			},
		},
		{
			name: "untagged fields with tagged nested",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type nestedStruct struct {
					Content string `sanitize:"strict"`
				}

				input := struct {
					TaggedField    string `sanitize:"strict"`
					UntaggedField  string
					UntaggedNested nestedStruct
				}{
					TaggedField:   "<script>alert('xss')</script>Tagged",
					UntaggedField: "<script>alert('xss')</script>Untagged",
					UntaggedNested: nestedStruct{
						Content: "<script>alert('xss')</script>Nested Content",
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Tagged", input.TaggedField)
				assert.Equal(t, "<script>alert('xss')</script>Untagged", input.UntaggedField)
				assert.Equal(t, "Nested Content", input.UntaggedNested.Content)
			},
		},
		{
			name: "untagged slice with tagged elements",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type nestedStruct struct {
					Content string `sanitize:"strict"`
				}

				input := struct {
					TaggedField   string `sanitize:"strict"`
					UntaggedSlice []nestedStruct
				}{
					TaggedField: "<script>alert('xss')</script>Tagged",
					UntaggedSlice: []nestedStruct{
						{Content: "<script>alert('xss')</script>Slice Content 1"},
						{Content: "<script>alert('xss')</script>Slice Content 2"},
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Tagged", input.TaggedField)
				assert.Equal(t, "Slice Content 1", input.UntaggedSlice[0].Content)
				assert.Equal(t, "Slice Content 2", input.UntaggedSlice[1].Content)
			},
		},
		{
			name: "untagged map with tagged elements",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type nestedStruct struct {
					Content string `sanitize:"strict"`
				}

				input := struct {
					TaggedField string `sanitize:"strict"`
					UntaggedMap map[string]nestedStruct
				}{
					TaggedField: "<script>alert('xss')</script>Tagged",
					UntaggedMap: map[string]nestedStruct{
						"key1": {Content: "<script>alert('xss')</script>Map Content 1"},
						"key2": {Content: "<script>alert('xss')</script>Map Content 2"},
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Tagged", input.TaggedField)
				assert.Equal(t, "Map Content 1", input.UntaggedMap["key1"].Content)
				assert.Equal(t, "Map Content 2", input.UntaggedMap["key2"].Content)
			},
		},
		{
			name: "skip tag ignores nested",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type nestedStruct struct {
					StrictField string `sanitize:"strict"`
					UGCField    string `sanitize:"ugc"`
				}

				input := struct {
					TaggedField   string       `sanitize:"strict"`
					SkippedNested nestedStruct `sanitize:"-"`
				}{
					TaggedField: "<script>alert('xss')</script>Tagged",
					SkippedNested: nestedStruct{
						StrictField: "<script>alert('xss')</script>Nested Strict",
						UGCField:    "<script>alert('xss')</script>Nested UGC",
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Tagged", input.TaggedField)
				assert.Equal(t, "<script>alert('xss')</script>Nested Strict", input.SkippedNested.StrictField)
				assert.Equal(t, "<script>alert('xss')</script>Nested UGC", input.SkippedNested.UGCField)
			},
		},
		{
			name: "completely untagged nested",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type completelyUntagged struct {
					Content string
				}

				input := struct {
					TaggedField        string `sanitize:"strict"`
					CompletelyUntagged completelyUntagged
				}{
					TaggedField: "<script>alert('xss')</script>Tagged",
					CompletelyUntagged: completelyUntagged{
						Content: "<script>alert('xss')</script>Untagged Content",
					},
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Tagged", input.TaggedField)
				assert.Equal(t, "<script>alert('xss')</script>Untagged Content", input.CompletelyUntagged.Content)
			},
		},
		{
			name: "generics",
			run: func(t *testing.T, s *stzr.Sanitizer) {
				type optional[T any] struct {
					Value T `sanitize:"strict"`
					Set   bool
				}

				input := optional[string]{
					Value: "<script>alert('xss')</script>Tagged",
					Set:   true,
				}

				require.NoError(t, s.SanitizeStruct(&input))
				assert.Equal(t, "Tagged", input.Value)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []stzr.Opt{
				stzr.WithPolicy("strict", bluemonday.StrictPolicy()),
				stzr.WithPolicy("ugc", bluemonday.UGCPolicy()),
			}

			opts = append(opts, tt.options...)
			s := stzr.New(opts...)
			if tt.setup != nil {
				tt.setup(s)
			}
			tt.run(t, s)
		})
	}
}

// Note: All tests on global instance should be run here and cleanup properly.
func TestGlobal(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*testing.T)
		run     func(*testing.T)
		wantErr bool
	}{
		{
			name:  "default with strict policy",
			setup: func(t *testing.T) {},
			run: func(t *testing.T) {
				s := stzr.Default()
				result, err := s.SanitizeString("strict", "<script>alert('xss')</script>Hello <b>World</b>")
				require.NoError(t, err)
				assert.Equal(t, "Hello World", result)
			},
		},
		{
			name:  "default with ugc policy",
			setup: func(t *testing.T) {},
			run: func(t *testing.T) {
				s := stzr.Default()
				result, err := s.SanitizeString("ugc", "<script>alert('xss')</script>Hello <b>World</b>")
				require.NoError(t, err)
				assert.Equal(t, "Hello <b>World</b>", result)
			},
		},
		{
			name: "default with custom policy",
			setup: func(t *testing.T) {
				customSanitizer := stzr.New(
					stzr.WithPolicy("custom", stzr.PolicyFunc(func(s string) string {
						return "CUSTOM: " + s
					})),
				)
				stzr.SetDefault(customSanitizer)
			},
			run: func(t *testing.T) {
				s := stzr.Default()
				result, err := s.SanitizeString("custom", "test")
				require.NoError(t, err)
				assert.Equal(t, "CUSTOM: test", result)
			},
		},
		{
			name:  "global sanitize string call",
			setup: func(t *testing.T) {},
			run: func(t *testing.T) {
				result, err := stzr.SanitizeString("strict", "<script>alert('xss')</script>Hello <b>World</b>")
				require.NoError(t, err)
				assert.Equal(t, "Hello World", result)
			},
		},
		{
			name:  "global sanitize struct call",
			setup: func(t *testing.T) {},
			run: func(t *testing.T) {
				input := struct {
					Field string `sanitize:"strict"`
				}{
					Field: "<script>alert('xss')</script>Hello <b>World</b>",
				}
				err := stzr.SanitizeStruct(&input)
				require.NoError(t, err)
				assert.Equal(t, "Hello World", input.Field)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := stzr.Default()
			t.Cleanup(func() {
				stzr.SetDefault(original)
			})

			if tt.setup != nil {
				tt.setup(t)
			}
			tt.run(t)
		})
	}
}

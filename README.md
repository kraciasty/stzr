# stzr

[![Go Reference](https://pkg.go.dev/badge/github.com/kraciasty/stzr.svg)](https://pkg.go.dev/github.com/kraciasty/stzr)
[![Go Report Card](https://goreportcard.com/badge/github.com/kraciasty/stzr)](https://goreportcard.com/report/github.com/kraciasty/stzr)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/kraciasty/stzr)
![GitHub](https://img.shields.io/github/license/kraciasty/stzr)
[![codecov](https://codecov.io/gh/kraciasty/stzr/graph/badge.svg?token=AFV16W16G9)](https://codecov.io/gh/kraciasty/stzr)

HTML sanitization using struct tags. Powered by [bluemonday](https://github.com/microcosm-cc/bluemonday).

## Rationale

_Becoming fed up with **manually sanitizing every string field** in complex nested structures, I created a **tag-based approach** to handle HTML sanitization declaratively._

## Features

A sane input sanitization experience:

- **Tag-based** - just add the tag
- **Recursive** - handles nested structs, slices, maps, pointers, generics
- Built-in **policies**: `strict` and `ugc` powered by [bluemonday policies](https://pkg.go.dev/github.com/microcosm-cc/bluemonday#Policy)
- **Extensible** with policies or custom functions

## Quickstart

```bash
go get -u github.com/kraciasty/stzr
```

### Basic Usage

```go
import "github.com/kraciasty/stzr"

type Character struct {
    Name string `sanitize:"strict"`
    Bio  string `sanitize:"ugc"`
}

character := &Character{
    Name: `<script>alert('morty')</script>Rick <b>Sanchez</b>`,
    Bio:  `Genius <b>scientist</b> from dimension C-137 <script>alert('wubba lubba dub dub')</script>`,
}

stzr.SanitizeStruct(character)
// Name: "Rick Sanchez"
// Bio:  "Genius <b>scientist</b> from dimension C-137"
```

> [!NOTE]
> **Nested structures work automatically** - structs, slices, maps, and pointers are processed recursively:
>
> ```go
> type Episode struct {
>     Title          string    `sanitize:"strict"`
>     Description    string    `sanitize:"ugc"`
>     Comments       []Comment // Nested structs handled automatically
>     SkippedComment Comment   `sanitize:"-"` // Skipped
> }
>
> type Comment struct {
>     Text       string `sanitize:"ugc"`
>     Author     string `sanitize:"strict"`
>     Dimension  string `sanitize:"strict"`
> }
> ```

### String Sanitization

```go
clean, err := stzr.SanitizeString("ugc", `<script>bad</script>Wubba lubba <b>dub dub</b>!`)
// Returns: "Wubba lubba <b>dub dub</b>!"
```

<details>
<summary><strong>Custom Policies</strong></summary>

```go
minimal := bluemonday.NewPolicy().AllowElements("b", "i")
links := bluemonday.NewPolicy().
    AllowElements("a").
    AllowAttrs("href").
    OnElements("a")

sanitizer := stzr.New(
    stzr.WithPolicy("minimal", minimal),
    stzr.WithPolicy("links", links),
)

type Blog struct {
    Content string `sanitize:"minimal"`
    Footer  string `sanitize:"links"`
}
```

</details>

<details>
<summary><strong>Integration with oapi-codegen</strong></summary>

Add `x-oapi-codegen-extra-tags` to your OpenAPI spec:

```yaml
# openapi.yml
components:
  schemas:
    CreateCharacterRequest:
      type: object
      properties:
        name:
          type: string
          x-oapi-codegen-extra-tags: # <---
            sanitize: "strict"       # strict policy
        backstory:
          type: string
          x-oapi-codegen-extra-tags: # <---
            sanitize: "ugc"          # ugc policy
```

Generates:

```go
type CreateCharacterRequest struct {
    Name      string `json:"name" sanitize:"strict"`
    Backstory string `json:"backstory" sanitize:"ugc"`
}
```

</details>

<details>
<summary><strong>Integration with Protocol Buffers</strong></summary>

Use something like [protoc-go-inject-tag](https://github.com/favadi/protoc-go-inject-tag) to add sanitization tags to generated protobuf structs:

```protobuf
// character.proto
message CreateCharacterRequest {
  string name = 1;      // @inject_tag: sanitize:"strict"
  string backstory = 2; // @inject_tag: sanitize:"ugc"
}
```

After generation, run:

```bash
protoc-go-inject-tag -input="*.pb.go"
```

Results in:

```go
type CreateCharacterRequest struct {
    Name      string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty" sanitize:"strict"`
    Backstory string `protobuf:"bytes,2,opt,name=backstory,proto3" json:"backstory,omitempty" sanitize:"ugc"`
}
```

</details>

## Documentation

For the Go code documentation reference - check [pkg.go.dev](https://pkg.go.dev/github.com/kraciasty/stzr).

## Contributing

Contributions are welcome!
If you find any issues or want to enhance the project, please submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.
// go build gen/* && ./codegen.exe pack/unpack.go  pack/marshaller.go
// go run pack/*
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"reflect"
	"strconv"
	"strings"
	"text/template"
)

//
// Creators
//

func createModel(currType *ast.TypeSpec) ValidationEntry {
	return ValidationEntry{structType: currType.Name.Name, validation: make([]Validation, 0)}
}

//
// Method type
//
type MethodApiGen struct {
	Method string `json:"method"`
	Url    string `json:"url"`
	Auth   bool   `json:"auth"`
}

type MethodEntry struct {
	meta       MethodApiGen
	refName    string
	refType    string
	methodName string
	returnType string
	paramType  string
}

type MethodsHandlers struct {
	handlers []MethodEntry
}

func (h *MethodsHandlers) generateHandlers() string {
	byType := make(map[string][]MethodEntry)

	for _, handler := range h.handlers {
		_, exists := byType[handler.refType]
		if !exists {
			byType[handler.refType] = make([]MethodEntry, 0)
		}
		byType[handler.refType] = append(byType[handler.refType], handler)
	}

	// types...
	codeSnippets := make([]string, 0)
	for _, handler := range h.handlers {
		codeSnippets = append(codeSnippets, strings.NewReplacer(
			"{returnType}", handler.returnType,
		).Replace(strings.ReplaceAll(`
type {returnType}ApiResponse struct {
	Error  string   ?json:"error"?
	Result *{returnType} ?json:"response,omitempty"?
}
`, "?", "`")))
	}

	for rt, mhs := range byType {
		cases := make([]string, 0)

		for _, mh := range mhs {
			var authSnippet string
			if mh.meta.Auth {
				authSnippet = `
			reqAuth := request.Header.Get("X-Auth") == "100500"
			if !reqAuth {
				sendHttpError(writer, http.StatusForbidden, "unauthorized")
				return
			}
`
			} else {
				authSnippet = ""
			}

			var httpMethodSnippet string
			if mh.meta.Method != "" {
				httpMethodSnippet = strings.NewReplacer(
					"{httpMethod}", mh.meta.Method,
				).Replace(`
			if request.Method != "{httpMethod}" {
				sendHttpError(writer, http.StatusNotAcceptable, "bad method")
				return
			}
`)
			} else {
				httpMethodSnippet = ""
			}

			cases = append(cases, strings.NewReplacer(
				"{url}", mh.meta.Url,
				"{authSnippet}", authSnippet,
				"{httpMethodSnippet}", httpMethodSnippet,
				"{returnType}", mh.returnType,
				"{refName}", mh.refName,
				"{refType}", mh.refType,
				"{paramType}", mh.paramType,
				"{methodName}", mh.methodName,
			).Replace(`
	case "{url}":
		{
			{authSnippet}

			{httpMethodSnippet}

			create, err := obtain_{paramType}(request)
			if err != nil {
				sendHttpError(writer, http.StatusBadRequest, err.Error())
				return
			}

			validated, err := validate_{paramType}(create)
			if err != nil {
				sendHttpError(writer, http.StatusBadRequest, err.Error())
				return
			}

			result, err := {refName}.{methodName}(request.Context(), validated)
			if err != nil {
				sendError(writer, err)
				return
			}

			data, _ := json.Marshal({returnType}ApiResponse{"", result})
			writer.Write(data)
		}
		`))
		}

		codeSnippets = append(codeSnippets, strings.NewReplacer(
			"{refName}", mhs[0].refName,
			"{refType}", rt,
			"{cases}", strings.Join(cases, ""),
		).Replace(`
func ({refName} *{refType}) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	
	{cases}

	default:
		{
			sendHttpError(writer, http.StatusNotFound, "unknown method")
		}
	}
}
		`))
	}

	return strings.Join(codeSnippets, "")
}

//
// Model type
//
func (v *ValidationEntry) validate(identifier *ast.Ident, field *ast.Field, apivalidator string) {
	validation := Validation{}
	validation.fieldName = field.Names[0].Name
	validation.fill(identifier.Name, apivalidator)
	v.validation = append(v.validation, validation)
}

func (v *ValidationEntry) empty() bool {
	return len(v.validation) == 0
}

func (v *ValidationEntry) generateObtainFunction() string {
	var intValues = make(map[string]string)
	for _, val := range v.validation {
		if val.paramType == "int" {
			intValues[val.paramName] = strings.NewReplacer(
				"{paramName}", val.paramName,
				"{structType}", v.structType,
			).Replace(`
	{paramName}, err := int_val(params, "{paramName}")
	if err != nil {
		return {structType}{}, err
	}
`)
		}
	}

	var ints = make([]string, 0)
	var fields = make([]string, 0)
	for _, val := range v.validation {
		curr, ok := intValues[val.paramName]
		if ok {
			ints = append(ints, curr)
			fields = append(fields, fmt.Sprintf(`%s: %s,`, val.fieldName, val.paramName))
		} else {
			fields = append(fields, fmt.Sprintf(`%s: params["%s"],`, val.fieldName, val.paramName))
		}
	}

	obtainFunction := `
func obtain_{structType}(request *http.Request) ({structType}, error) {
	params := payloadToMap(request)

	{ints}

	createParams := {structType}{
		{fields}
	}

	return createParams, nil
}
`
	return strings.NewReplacer(
		"{structType}", v.structType,
		"{ints}", strings.Join(ints, "\n"),
		"{fields}", strings.Join(fields, "\n"),
	).Replace(obtainFunction)

}

func (v *ValidationEntry) generateValidationFunction() string {
	validationFunction := `
func validate_{structType}(params {structType}) ({structType}, error) {
	var e error
	{body}

	return params, e
}
`
	functions := make([]string, 0)
	for _, val := range v.validation {
		for _, function := range val.generateValidationFunction(v.structType) {
			functions = append(functions, function)
		}
	}

	return strings.NewReplacer(
		"{structType}", v.structType,
		"{body}", strings.Join(functions, "\n"),
	).Replace(validationFunction)
}

type ValidationEntry struct {
	structType string
	validation []Validation
}

type Enum struct {
	values       string
	defaultValue string
}

type Length struct {
	isMax    bool
	isMin    bool
	maxValue int
	minValue int
}

type Validation struct {
	isRequired bool
	paramName  string
	enum       Enum
	paramType  string
	length     Length
	fieldName  string
}

func (v *Validation) generateValidationFunction(structType string) []string {
	validationFunctions := make([]string, 0)

	if v.isRequired {
		validationFunctions = append(validationFunctions, strings.NewReplacer(
			"{structType}", structType,
			"{paramType}", v.paramType,
			"{paramName}", v.paramName,
			"{fieldName}", v.fieldName,
		).Replace(
			`
	e = validate_{paramType}_required("{paramName}", params.{fieldName})
	if e != nil {
		return {structType}{}, e
	}`,
		))
	}

	if v.enum.defaultValue != "" {
		validationFunctions = append(validationFunctions, strings.NewReplacer(
			"{structType}", structType,
			"{paramType}", v.paramType,
			"{paramName}", v.paramName,
			"{fieldName}", v.fieldName,
			"{enums}", v.enum.values,
			"{defaultValue}", v.enum.defaultValue,
		).Replace(
			`
	enumDefault, e := validate_enum("{paramName}", params.{fieldName}, strings.Split("{enums}", "|"), "{defaultValue}")
	if enumDefault != "" {
		params.{fieldName} = enumDefault
	}
	if e != nil {
		return {structType}{}, e
	}
`,
		))
	}

	if v.length.isMin || v.length.isMax {
		types := make([]string, 0)
		values := make([]int, 0)

		if v.length.isMin {
			types = append(types, "min")
			values = append(values, v.length.minValue)
		}
		if v.length.isMax {
			types = append(types, "max")
			values = append(values, v.length.maxValue)
		}

		for index, typePrefix := range types {
			var lengthType string
			if v.paramType == "string" {
				lengthType = "_len"
			} else {
				lengthType = ""
			}
			validationFunctions = append(validationFunctions, strings.NewReplacer(
				"{structType}", structType,
				"{paramType}", v.paramType,
				"{paramName}", v.paramName,
				"{fieldName}", v.fieldName,
				"{typePrefix}", typePrefix,
				"{lengthType}", lengthType,
				"{value}", fmt.Sprint(values[index]),
			).Replace(
				`
	e = validate_{paramType}_{typePrefix}{lengthType}("{paramName}", params.{fieldName}, {value})
	if e != nil {
		return {structType}{}, e
	}
`,
			))
		}
	}

	return validationFunctions
}

func (v *Validation) fill(paramType string, tagValue string) {
	v.paramType = paramType

	for _, validation := range strings.Split(tagValue, ",") {
		v.paramName = strings.ToLower(v.fieldName)

		if "required" == validation {
			v.isRequired = true
			continue
		}
		pair := strings.Split(validation, "=")
		if "default" == pair[0] {
			v.enum.defaultValue = pair[1]
		} else if "enum" == pair[0] {
			v.enum.values = pair[1]
		} else if "paramname" == pair[0] {
			v.paramName = pair[1]
		} else {
			// length validation
			intValue, _ := strconv.Atoi(pair[1])

			if "min" == pair[0] {
				v.length.isMin = true
				v.length.minValue = intValue

			}
			if "max" == pair[0] {
				v.length.isMax = true
				v.length.maxValue = intValue
			}
		}
	}

}

var (
	structsCode = strings.ReplaceAll(`
type ErrResponse struct {
	Error string ?json:"error"?
}
`, "?", "`")

	utilitiesCode = `
//
// utilities
//
func sendError(writer http.ResponseWriter, err error) {
	if apiError, ok := err.(ApiError); ok {
		sendHttpError(writer, apiError.HTTPStatus, apiError.Error())
	} else {
		sendHttpError(writer, http.StatusInternalServerError, err.Error())
	}
}

func sendHttpError(writer http.ResponseWriter, code int, description string) {
	writer.WriteHeader(code)
	data, _ := json.Marshal(ErrResponse{description})
	writer.Write(data)
}

//
// no Go1.18 on the Coursera server :troll:
//
func cut(s, sep string) (before, after string, found bool) {
	if i := strings.Index(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

func toMap(uri string) map[string]string {
	result := map[string]string{}
	var query string

	before, after, found := cut(uri, "?")

	if found {
		query = after
	} else {
		query = before
	}

	if query == "" {
		return result
	}

	kvs := strings.Split(query, "&")
	for _, each := range kvs {
		if each != "" {
			kv := strings.Split(each, "=")
			result[kv[0]] = kv[1]
		}
	}

	return result
}

func payloadToMap(request *http.Request) map[string]string {
	var m map[string]string

	if request.Method == "GET" {
		m = toMap(request.RequestURI)
	} else {
		defer request.Body.Close()
		body, _ := ioutil.ReadAll(request.Body)
		m = toMap(string(body))
	}
	return m
}

//
// bunch of validation methods
//
func validate_enum(name string, value string, enums []string, enumDefault string) (string, error) {
	if value == "" {
		return enumDefault, nil
	}

	for _, enum := range enums {
		if value == enum {
			return "", nil
		}
	}
	return "", errors.New(fmt.Sprintf("%s %s [%s]", name, "must be one of", strings.Join(enums, ", ")))
}

func validate_string_min_len(name string, value string, min int) error {
	if len(value) <= min {
		return errors.New(fmt.Sprintf("%s %s %d", name, "len must be >=", min))
	}

	return nil
}

func validate_string_required(name string, value string) error {
	if value == "" {
		return errors.New(fmt.Sprintf("%s %s", name, "must me not empty"))
	}

	return nil
}

func validate_int_min(name string, value int, min int) error {
	if value < min {
		return errors.New(fmt.Sprintf("%s %s %d", name, "must be >=", min))
	}

	return nil
}

func validate_int_max(name string, value int, max int) error {
	if value > max {
		return errors.New(fmt.Sprintf("%s %s %d", name, "must be <=", max))
	}

	return nil
}

//
// conversion
//

func int_val(m map[string]string, k string) (int, error) {
	s := m[k]

	if s == "" {
		return 0, nil
	}

	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, errors.New(fmt.Sprintf("%s %s", k, "must be int"))
	}
	return v, nil
}


`

	importsCode = `
import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
)
`

	obtainParameterTpl = template.Must(template.New("obtainParameter").Parse(`
	func obtain_{{index .structType}}(request *http.Request) ({{index .structType}}, error) {
		m := payloadToMap(request)
	
		return {{index .structType}}{

		}, nil
	}
`))

	strTpl = template.Must(template.New("strTpl").Parse(`
	// {{.FieldName}}
	var {{.FieldName}}LenRaw uint32
	binary.Read(r, binary.LittleEndian, &{{.FieldName}}LenRaw)
	{{.FieldName}}Raw := make([]byte, {{.FieldName}}LenRaw)
	binary.Read(r, binary.LittleEndian, &{{.FieldName}}Raw)
	in.{{.FieldName}} = string({{.FieldName}}Raw)
`))
)

func main() {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, os.Args[1], nil, parser.ParseComments)
	if err != nil {
		log.Fatal(err)
	}

	out, _ := os.Create(os.Args[2])

	fmt.Fprintln(out, `package `+node.Name.Name)
	fmt.Fprintln(out, importsCode, structsCode, utilitiesCode)

	//
	// Metadata collection
	//
	var model = make([]ValidationEntry, 0)
	handlers := MethodsHandlers{}

	for _, declaration := range node.Decls {
		f, ok := declaration.(*ast.FuncDecl)
		if ok {
			if f.Doc != nil {
				comment := f.Doc.Text()
				index := strings.Index(comment, "apigen:api")
				if index >= 0 {
					refName := f.Recv.List[0].Names[0].Name
					methodName := f.Name.Name
					returnType := f.Type.Results.List[0].Type.(*ast.StarExpr).X.(*ast.Ident).Name
					paramType := f.Type.Params.List[1].Type.(*ast.Ident).Name

					starExpr, casted := f.Recv.List[0].Type.(*ast.StarExpr)
					if casted {
						ident, casted := starExpr.X.(*ast.Ident)
						if casted {
							refType := ident.Name

							methodInfo := MethodApiGen{}
							info := comment[index+len("apigen:api"):]
							json.Unmarshal([]byte(info), &methodInfo)

							entry := MethodEntry{methodInfo, refName, refType, methodName, returnType, paramType}
							handlers.handlers = append(handlers.handlers, entry)
						}
					}
				}
			}

			continue
		}

		g, ok := declaration.(*ast.GenDecl)
		if !ok {
			fmt.Printf("SKIP %T is not *ast.GenDecl\n", declaration)
			continue
		}

		for _, spec := range g.Specs {

			currType, ok := spec.(*ast.TypeSpec)
			if !ok {
				fmt.Printf("SKIP %T is not ast.TypeSpec\n", spec)
				continue
			}

			currStruct, ok := currType.Type.(*ast.StructType)
			if !ok {
				fmt.Printf("SKIP %T is not ast.StructType\n", currStruct)
				continue
			}

			validationEntry := createModel(currType)

			for _, field := range currStruct.Fields.List {
				if field.Tag != nil {
					tag := reflect.StructTag(field.Tag.Value[1 : len(field.Tag.Value)-1])

					apivalidator, found := tag.Lookup("apivalidator")
					if found {
						identifier, ok := field.Type.(*ast.Ident)
						if ok {
							validationEntry.validate(identifier, field, apivalidator)

							fmt.Printf("#### tag %s: %s\n", apivalidator, currType.Name)
						}
					}
				}
			}

			if !validationEntry.empty() {
				model = append(model, validationEntry)
			}

		}

	}

	//
	// Code generation
	//
	for _, validationEntry := range model {
		fmt.Fprintln(out, validationEntry.generateObtainFunction())
	}

	for _, validationEntry := range model {
		fmt.Fprintln(out, validationEntry.generateValidationFunction())
	}

	fmt.Fprintln(out, handlers.generateHandlers())
}

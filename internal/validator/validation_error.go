package validator

// ValidationError contains validation information.
type validationError struct {
	// Field is the fields name with the JSON tag name taking precedence.
	// E.g. "code" for a struct containing Code `json:"code"`
	// or "address[0]" for a Address field that is of type []string
	Field string

	// StructField is the field's value from the struct
	// E.g. "Code" for a struct containing Code `json:"code"`
	StructField string

	// Value is the actual value of the field from the client.
	// E.g. if the request contained { "code": 123 } then the Value contains
	// 123.
	Value interface{}

	// Tag is the validation tag that failed.
	// E.g. min given the validation rule `validate:"min=30"`
	Tag string

	// Returns the validation tag value.
	// E.g. "30" for a value that was too short with validation rule
	// `validate:"min=30"`
	// or "openid" for a value that was validated with
	// `validate:"oneof=openid"`
	Param string
}

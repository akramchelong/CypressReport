package validator

// A ErrorBag contains multiple errors.
// A more generic solution would be to instead store elements that implement
// the "error" interface, however, that makes a generic add function harder,
// since there is no identifier.
type ErrorBag map[string]*validationError

// FailedOn returns true if the error bag contains the field, i.e. the
// validation for that field failed.
func (errorBag ErrorBag) FailedOn(field string) bool {
	_, exists := errorBag[field]

	return exists
}

// Add adds a new validation error to the bag.
func (errorBag ErrorBag) Add(err *validationError) {
	errorBag[err.Field] = err
}

// Empty returns true if the error bag is empty.
func (errorBag ErrorBag) Empty() bool {
	return len(errorBag) == 0
}

// GetErrorsFor returns a new error bag that only contain the provided fields.
// Note that this does not return errors for a field array, so for instance
// argument "scope" will not include scope[0].
func (errorBag ErrorBag) GetErrorsFor(fields ...string) ErrorBag {
	subsetErrorBag := make(ErrorBag)

	for _, field := range fields {
		err, exists := errorBag[field]
		if exists {
			subsetErrorBag.Add(err)
		}
	}

	return subsetErrorBag
}

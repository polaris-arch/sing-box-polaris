package box

import "context"

// constructionValidationKey selects complete original constructor validation.
// It is private: normal runtime constructors and transactions never set it.
type constructionValidationKey struct{}

func isConstructionValidation(ctx context.Context) bool {
	validation, _ := ctx.Value(constructionValidationKey{}).(bool)
	return validation
}

// NewForValidationWithConstructionReport constructs an instance solely for
// configuration validation and disposal. The caller must close it without
// starting it. Unlike runtime preparation, this path runs the original
// constructors now, including their validation and original store census.
// It never invokes Start or runtime staging and does not prove live availability.
// Original constructors can acquire resources; their cleanup errors retain
// NewWithConstructionReport semantics, without claiming exact global disposal.
func NewForValidationWithConstructionReport(options Options) (*Box, ConstructionReport, error) {
	ctx := options.Context
	if ctx == nil {
		ctx = context.Background()
	}
	options.Context = context.WithValue(ctx, constructionValidationKey{}, true)
	instance, err, report := NewWithConstructionReport(options)
	return instance, report, err
}

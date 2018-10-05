package micro_kit

import (
	"fmt"
	"github.com/go-playground/validator"
	"strings"
)

type ServiceError struct {
	Code             int               `json:"code"`
	Message          string            `json:"message,omitempty"`
	Previous         string            `json:"previous,omitempty"`
	ValidationErrors map[string]string `json:"validationErrors,omitempty"`
}

func NewServiceError(code int, message string, previous error) *ServiceError {
	err := &ServiceError{
		Code:             code,
		Message:          message,
		ValidationErrors: make(map[string]string),
	}

	if previous != nil {
		err.Previous = err.Error()
	}

	return err
}

func NewValidationError(validationErrors validator.ValidationErrors) *ServiceError {
	err := NewServiceError(405, "Bad request.", validationErrors)

	for _, fieldError := range validationErrors {
		err.ValidationErrors[fieldError.StructField()] = fieldError.Tag()
	}

	return err
}

func (e *ServiceError) Error() string {
	err := "Error. "

	if e.Code > 0 {
		err += fmt.Sprintf("Code %d. ", e.Code)
	}

	if e.Message != "" {
		err += fmt.Sprintf("Message: %s. ", e.Message)
	}

	if e.Previous != "" {
		err += fmt.Sprintf("Prvious error message: %s. ", e.Previous)
	}

	return strings.TrimSuffix(err, " ")
}

type ErrorResponse struct {
	Payload *ServiceError `json:"payload"`
}

package micro_kit

import (
	"context"
	"encoding/json"
	jwtGo "github.com/dgrijalva/jwt-go"
	"github.com/go-playground/validator"
	"github.com/sirupsen/logrus"
	"net/http"
)

const (
	bearer       string = "bearer"
	bearerFormat string = "Bearer %s"
)

type JwtClaims struct {
	UserId string   `json:"userId"`
	Roles  []string `json:"roles"`
	*jwtGo.StandardClaims
}

type ResponseEncoder struct {
	logger logrus.FieldLogger
}

func (e *ResponseEncoder) Encoder(_ context.Context, w http.ResponseWriter, response interface{}) error {
	e.logger.
		WithField("response", response).
		Info("Encoding response.")

	return json.NewEncoder(w).Encode(response)
}

func (e *ResponseEncoder) EncodeError(ctx context.Context, err error, w http.ResponseWriter) {
	if err == nil {
		e.logger.
			WithError(err).
			WithField("context", ctx).
			Warn("No error to encode.")
	} else {
		e.logger.
			WithError(err).
			Infof("Encoding error: %s", err)
	}

	var serviceErr *ServiceError

	if castedErr, ok := err.(*ServiceError); ok {
		serviceErr = castedErr
	} else if validationErrors, ok := err.(validator.ValidationErrors); ok {
		serviceErr = NewValidationError(validationErrors)
	} else if jwtError, ok := err.(*jwtGo.ValidationError); ok {
		serviceErr = e.HandleJwtError(jwtError, serviceErr)
	} else {
		serviceErr = NewServiceError(500, "Something went wrong.", err)
	}

	if serviceErr.Code != 0 {
		w.WriteHeader(serviceErr.Code)
	} else {
		w.WriteHeader(500)
	}

	encoderErr := json.NewEncoder(w).Encode(ErrorResponse{serviceErr})

	if encoderErr != nil {
		e.logger.
			WithError(err).
			Error("Failed to encode error.")
	}
}

func (e *ResponseEncoder) HandleJwtError(jwtError *jwtGo.ValidationError, serviceErr *ServiceError) *ServiceError {
	switch {
	case jwtError.Errors&jwtGo.ValidationErrorMalformed != 0:
		serviceErr = NewServiceError(400, "Malformed JWT token.", jwtError)
		break
	case jwtError.Errors&jwtGo.ValidationErrorExpired != 0:
	case jwtError.Errors&jwtGo.ValidationErrorNotValidYet != 0:
		serviceErr = NewServiceError(403, "Invalid JWT token", jwtError)
		break
	case jwtError.Inner != nil:
		serviceErr = NewServiceError(500, "Something when wrong.", jwtError.Inner)
		break
	default:
		serviceErr = NewServiceError(500, "Something when wrong.", jwtError)
		break
	}
	return serviceErr
}

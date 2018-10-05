package micro_kit

import (
	"context"
	"crypto/rsa"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/dgrijalva/jwt-go"
	jwtAuth "github.com/go-kit/kit/auth/jwt"
	"github.com/go-kit/kit/endpoint"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"net/http"
	"os"
	"strings"
)

type Service struct {
	logsFormatter   logrus.Formatter
	logger          logrus.FieldLogger
	awsSession      *session.Session
	validateKey     *rsa.PublicKey
	jwtMiddleware   endpoint.Middleware
	serverOptions   []httptransport.ServerOption
	responseEncoder *ResponseEncoder
	router          *mux.Router
}

func (s *Service) GetLogger() logrus.FieldLogger {
	if s.logger == nil {
		logger := logrus.New()
		logger.SetLevel(s.getLogLevel())
		logger.Formatter = s.GetLogsFormatter()

		s.logger = logger
	}

	return s.logger
}

func (s *Service) GetLogsFormatter() logrus.Formatter {
	if s.logsFormatter == nil {
		s.logsFormatter = &logrus.JSONFormatter{}
	}

	return s.logsFormatter
}

func (s *Service) getLogLevel() logrus.Level {
	lvl, err := logrus.ParseLevel(os.Getenv("LOG_LEVEL"))

	if err != nil {
		return logrus.DebugLevel
	}

	return lvl
}

func (s *Service) GetAwsSession() (*session.Session, error) {
	if s.awsSession == nil {
		awsSession, err := session.NewSession(&aws.Config{
			Region: aws.String(
				os.Getenv("AWS_REGION"),
			),
		})

		if err != nil {
			return nil, err
		}

		s.awsSession = awsSession
	}
	return s.awsSession, nil
}

func (s *Service) GetValidateKey() (*rsa.PublicKey, error) {
	if s.validateKey == nil {
		validateKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(os.Getenv("ID_RSA_PUB")))

		if err != nil {
			return nil, err
		}

		s.validateKey = validateKey
	}

	return s.validateKey, nil
}

func (s *Service) getJwtMiddleware() endpoint.Middleware {
	if s.jwtMiddleware == nil {
		s.jwtMiddleware = jwtAuth.NewParser(
			func(token *jwt.Token) (interface{}, error) { return s.GetValidateKey() },
			jwt.SigningMethodRS512,
			func() jwt.Claims { return &JwtClaims{} },
		)
	}

	return s.jwtMiddleware
}

func (s *Service) WrapWithJwtTokenValidation(endpoint endpoint.Endpoint) endpoint.Endpoint {
	return s.getJwtMiddleware()(endpoint)
}

func (s *Service) getResponseEncoder() *ResponseEncoder {
	if s.responseEncoder == nil {
		s.responseEncoder = &ResponseEncoder{s.GetLogger()}
	}

	return s.responseEncoder
}

func (s *Service) getServerOptions() []httptransport.ServerOption {
	if s.serverOptions == nil {
		s.serverOptions = []httptransport.ServerOption{
			httptransport.ServerErrorEncoder(s.getResponseEncoder().EncodeError),
			httptransport.ServerBefore(
				func(ctx context.Context, r *http.Request) context.Context {
					authHeaderParts := strings.Split(r.Header.Get("Authorization"), " ")

					if len(authHeaderParts) != 2 || strings.ToLower(authHeaderParts[0]) != bearer {
						return ctx
					}

					return context.WithValue(ctx, jwtAuth.JWTTokenContextKey, authHeaderParts[1])
				},
			),
		}
	}

	return s.serverOptions
}

func (s *Service) CreateHttpHandler(
	endpoint endpoint.Endpoint,
	requestDecoder func(context.Context, *http.Request) (interface{}, error),
) *httptransport.Server {
	return httptransport.NewServer(
		endpoint,
		requestDecoder,
		s.getResponseEncoder().Encoder,
		s.getServerOptions()...,
	)
}

func (s *Service) GetRouter() *mux.Router {
	if s.router == nil {
		s.router = mux.NewRouter()

		// add a ping endpoint by default
		s.router.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(200)
			w.Header().Add("Content-Type", "application/json")
			w.Write([]byte("{\"payload\":\"pong\"}"))
		})
	}

	return s.router
}

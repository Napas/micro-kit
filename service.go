package micro_kit

import (
	"context"
	"crypto/rsa"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
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

const AuthContextKey = "AuthContext"

type Service struct {
	logsFormatter   logrus.Formatter
	logger          logrus.FieldLogger
	awsSession      *session.Session
	validateKey     *rsa.PublicKey
	jwtMiddleware   endpoint.Middleware
	authMiddleware  endpoint.Middleware
	serverOptions   []httptransport.ServerOption
	responseEncoder *ResponseEncoder
	router          *mux.Router
	rolesMap        HavingRole
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
		config := &aws.Config{
			Region: aws.String(
				os.Getenv("AWS_REGION"),
			),
		}

		if s.getLogLevel() == logrus.DebugLevel {
			config.LogLevel = aws.LogLevel(aws.LogDebugWithHTTPBody)
			config.CredentialsChainVerboseErrors = aws.Bool(true)
		}

		awsSession, err := session.NewSession(config)

		if err != nil {
			return nil, err
		}

		s.awsSession = awsSession
	}
	return s.awsSession, nil
}

func (s *Service) GetValidateKey() (*rsa.PublicKey, error) {
	if s.validateKey == nil {
		buf := []byte{}
		stream := aws.NewWriteAtBuffer(buf)
		sess, err := s.GetAwsSession()

		if err != nil {
			s.logger.WithError(err).Errorf("Failed to download public key with error: ")
			return nil, err
		}

		downloader := s3manager.NewDownloader(sess)
		_, err = downloader.Download(
			stream, &s3.GetObjectInput{
				Bucket: aws.String(os.Getenv("ID_RSA_PUB_BUCKET")),
				Key:    aws.String(os.Getenv("ID_RSA_PUB_FILE")),
			})

		validateKey, err := jwt.ParseRSAPublicKeyFromPEM(stream.Bytes())

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
	return s.getJwtMiddleware()(
		s.getAuthMiddleware()(endpoint),
	)
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

		// set application/json as default content type
		s.router.Use(
			func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Add("Content-Type", "application/json; charset=utf-8")
					next.ServeHTTP(w, r)
				})
			},
		)

		// add a ping endpoint by default
		s.router.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("{\"payload\":\"pong\"}"))
		})
	}

	return s.router
}

func (s *Service) getAuthMiddleware() endpoint.Middleware {
	if s.authMiddleware == nil {
		s.authMiddleware = func(next endpoint.Endpoint) endpoint.Endpoint {
			return func(ctx context.Context, request interface{}) (response interface{}, err error) {
				claims, ok := ctx.Value(jwtAuth.JWTClaimsContextKey).(*JwtClaims)

				if !ok || claims == nil {
					claims = &JwtClaims{Roles: []string{ROLE_ANONYMOUS}}
				}

				auth := &Auth{claims, s.getRolesMap()}

				return next(context.WithValue(ctx, AuthContextKey, auth), request)
			}
		}
	}

	return s.authMiddleware
}

func (s *Service) getRolesMap() HavingRole {
	if s.rolesMap == nil {
		s.rolesMap = DefaultRolesMap()
	}

	return s.rolesMap
}

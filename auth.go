package micro_kit

import (
	"github.com/dgrijalva/jwt-go"
)

const ROLE_ANONYMOUS = "ROLE_ANONYMOUS"
const ROLE_USER = "ROLE_USER"
const ROLE_ADMIN = "ROLE_ADMIN"
const ROLE_SUPER_ADMIN = "ROLE_SUPER_ADMIN"

type HavingRole interface {
	HasRole(string) bool
}

type Role struct {
	Id       string
	Children []*Role
}

func (r *Role) HasRole(role string) bool {
	if r.Id == role {
		return true
	}

	if len(r.Children) > 0 {
		for _, child := range r.Children {
			if child.HasRole(role) {
				return true
			}
		}
	}

	return false
}

type HavingRoles interface {
	HasRole(string) bool
	GetRole(string) HavingRole
}

type RolesMap struct {
	Roles map[string]HavingRole
}

func (r *RolesMap) GetRole(role string) HavingRole {
	if role, ok := r.Roles[role]; ok {
		return role
	}

	return nil
}

func (r *RolesMap) HasRole(role string) bool {
	roleObj := r.GetRole(role)

	if roleObj == nil {
		return false
	}

	return roleObj.HasRole(role)
}

func DefaultRolesMap() *RolesMap {
	anonymous := &Role{Id: ROLE_ANONYMOUS}
	user := &Role{ROLE_USER, []*Role{anonymous}}
	admin := &Role{ROLE_ADMIN, []*Role{user}}
	superAdmin := &Role{ROLE_SUPER_ADMIN, []*Role{admin}}

	return &RolesMap{map[string]HavingRole{
		ROLE_ANONYMOUS:   anonymous,
		ROLE_USER:        user,
		ROLE_ADMIN:       admin,
		ROLE_SUPER_ADMIN: superAdmin,
	}}
}

type Auth struct {
	Claims   *JwtClaims
	RolesMap HavingRoles
}

func (auth *Auth) HasRole(role string) bool {
	if auth.Claims == nil || len(auth.Claims.Roles) == 0 {
		return false
	}

	for _, roleFromToken := range auth.Claims.Roles {
		role := auth.RolesMap.GetRole(roleFromToken)

		if role != nil && role.HasRole(roleFromToken) {
			return true
		}
	}

	return false
}

type JwtClaims struct {
	UserId string   `json:"userId"`
	Roles  []string `json:"roles"`
	*jwt.StandardClaims
}

package micro_kit

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"testing"
)

type RoleMock struct {
	mock.Mock
}

func (m *RoleMock) HasRole(role string) bool {
	return m.Called(role).Bool(0)
}

type RolesMapMock struct {
	mock.Mock
}

func (m *RolesMapMock) HasRole(role string) bool {
	return m.Called(role).Bool(0)
}

func TestRole_HasRole_ReturnsTrueIfIdMatches(t *testing.T) {
	role := Role{Id: "id"}

	assert.True(t, role.HasRole("id"))
}

func TestRole_HasRole_ReturnsTrueIfChildIdMatches(t *testing.T) {
	role := Role{
		"id",
		[]*Role{
			{
				Id: "matchingId",
			},
		},
	}

	assert.True(t, role.HasRole("matchingId"))
}

func TestRolesMap_GetRole_ReturnsRole(t *testing.T) {
	role := &Role{}
	rolesMap := RolesMap{
		map[string]HavingRole{
			"role": role,
		},
	}

	assert.Equal(t, role, rolesMap.GetRole("role"))
}

func TestRolesMap_GetRole_ReturnsNilIfRoleDoesNotExits(t *testing.T) {
	role := &Role{}
	rolesMap := RolesMap{
		map[string]HavingRole{
			"role": role,
		},
	}

	assert.Nil(t, rolesMap.GetRole("non existing role id"))
}

func TestRolesMap_HasRole_ReturnsFalseIfRoleDoesNotExistInTheMap(t *testing.T) {
	rolesMap := RolesMap{}

	assert.False(t, rolesMap.HasRole("role id"))
}

func TestRolesMap_HasRole_ChecksIfRoleExistsInReturnedRole(t *testing.T) {
	roleMock := new(RoleMock)
	roleMock.On("HasRole", "role id").Return(false)
	rolesMap := RolesMap{
		map[string]HavingRole{
			"role id": roleMock,
		},
	}

	rolesMap.HasRole("role id")

	roleMock.AssertCalled(t, "HasRole", "role id")
}

func TestRolesMap_HasRole_ReturnsResultResultFromHasRoleMethodOnRole(t *testing.T) {
	dataProvider := []bool{true, false}

	for _, res := range dataProvider {
		roleMock := new(RoleMock)
		roleMock.On("HasRole", "role id").Return(res)
		rolesMap := RolesMap{
			map[string]HavingRole{
				"role id": roleMock,
			},
		}

		assert.Equal(t, res, rolesMap.HasRole("role id"))
	}
}

func TestAuth_HasRole_ReturnsFalseIfClaimsObjectIsNotSet(t *testing.T) {
	auth := new(Auth)

	assert.False(t, auth.HasRole("role id"))
}

func TestAuth_HasRole_ReturnsFalseIfNoRolesAreSetInClaimsObject(t *testing.T) {
	claims := new(JwtClaims)
	auth := Auth{Claims: claims}

	assert.False(t, auth.HasRole("role id"))
}

func TestAuth_HasRole_ReturnsTrueIfAnyOfClaimsRoleHasIt(t *testing.T) {
	claims := &JwtClaims{Roles: []string{"id1", "id2"}}

	rolesMapMock := new(RolesMapMock)
	rolesMapMock.On("HasRole", "id1").Return(false)
	rolesMapMock.On("HasRole", "id2").Return(true)

	auth := Auth{claims, rolesMapMock}

	assert.True(t, auth.HasRole("id2"))
}

func TestAuth_HasRoleŽReturnsFalsIfNoneOfTheClaimsRolesIsAllowed(t *testing.T) {
	claims := &JwtClaims{Roles: []string{"id"}}

	rolesMapMock := new(RolesMapMock)
	rolesMapMock.On("HasRole", "id").Return(false)

	auth := Auth{claims, rolesMapMock}

	assert.False(t, auth.HasRole("id"))
}

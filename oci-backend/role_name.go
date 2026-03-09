package ocibackend

import "regexp"

var strictRoleNamePattern = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)

func isStrictRoleNameValid(name string) bool {
	return strictRoleNamePattern.MatchString(name)
}

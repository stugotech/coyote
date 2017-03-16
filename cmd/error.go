package cmd

import (
	"fmt"
)

// CommandError represents an error returned from a command
type CommandError struct {
	err  string
	code int
}

// NewCommandError creates an error with a specified return code
func NewCommandError(code int, err string) error {
	return &CommandError{err: err, code: code}
}

// NewCommandErrorF creates an error with a specified return code
func NewCommandErrorF(code int, format string, a ...interface{}) error {
	return &CommandError{err: fmt.Sprintf(format, a...), code: code}
}

// Error gets the error message
func (e *CommandError) Error() string {
	return e.err
}

// Code gets the error code
func (e *CommandError) Code() int {
	return e.code
}

// NewUserError creates a new user error
func NewUserError(err string) error {
	return NewCommandError(1, err)
}

// NewUserErrorF creates a new user error with a formatted string
func NewUserErrorF(format string, a ...interface{}) error {
	return NewCommandErrorF(1, format, a...)
}

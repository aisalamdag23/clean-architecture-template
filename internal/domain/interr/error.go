package interr

// NotFoundErr ...
const NotFoundErr = errorStr("Email does not exist.")
const UserNotActiveErr = errorStr("Sorry you cannot log in, Please verify your email address.")
const LoginCredentialsErr = errorStr("Incorrect username or password.")
const InvalidToken = errorStr("Invalid token")
const UnknownErr = errorStr("Unknown error")

// UnauthorizeErr ...
const UnauthorizeErr = errorStr("unauthorized")

// errorStr implements error interface
// and keeps primitive type's features (comparable, constants)
type errorStr string

// Error returns errorStr msg
// implements Error interface
func (err errorStr) Error() string {
	return string(err)
}

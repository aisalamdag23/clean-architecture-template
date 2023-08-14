package context

type CtxKey string

const (
	UserIDCtxKey CtxKey = "user_id"
)

func GetCtxKeyByIss(iss string) CtxKey {
	switch iss {
	case "users-api":
		return UserIDCtxKey
	}
	return UserIDCtxKey
}

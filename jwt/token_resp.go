package jwt

import "github.com/gogf/gf/v2/util/gconv"

const (
	Success           = 0
	Unauthorized      = 401 //未有TOKEN
	AuthorizedExptime = 402 //过期
	AuthorizedFail    = 403 //校验失败
)

type Resp struct {
	Code int
	Msg  string
	Data interface{}
}

func (r Resp) DataStrig() string {
	return gconv.String(r.Data)
}
func (r Resp) MsgStr() string {
	return r.Msg
}
func (r Resp) Succ() bool {
	return r.Code == Success
}
func AuthFail(msg string) Resp {
	return Resp{AuthorizedFail, msg, nil}
}

func Succ(data interface{}) Resp {
	return Resp{Success, "", data}
}
func SuccWithMsg(data interface{}, msg string) Resp {
	return Resp{Success, msg, data}
}
func UnauthFail(msg string, data interface{}) Resp {
	return Resp{Unauthorized, msg, data}
}

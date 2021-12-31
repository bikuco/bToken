package gf

import (
	"strings"
	"time"

	jwtToken "github.com/bikuco/bToken/jwt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
)

type Token struct {
	ServerName         string
	ExpTime            int64
	TokenSignKey       string //生成密钥
	LoginPath          string
	TokenHeaderName    string
	RefreshHeaderName  string
	LoginBeforeHandler func(r *ghttp.Request) (key string, userData interface{})
	LoginLastHandler   func(r *ghttp.Request, respData jwtToken.Resp)
	LogoutPath         string
	LogoutHandler      func(r *ghttp.Request)
	AuthAfterHandler   func(r *ghttp.Request, respData jwtToken.Resp)

	RefreshAfterHandler func(r *ghttp.Request, respData jwtToken.Resp) //刷新后操作
}

func (t *Token) InitConfig() {
	if t.ExpTime <= 0 {
		t.ExpTime = 5
	}
	if t.TokenSignKey == "" {
		t.TokenSignKey = "Sf2a45k68N9Vs2P2PofnMskifbeTsf2245"
	}
	if t.RefreshHeaderName == "" {
		t.RefreshHeaderName = "refreshToken"
	}
}
func (t *Token) Login(r *ghttp.Request) {
	userkey, userdata := t.LoginBeforeHandler(r)
	if userkey == "" || userdata == nil {
		return
	}
	Expired := time.Now().Add(time.Hour * time.Duration(t.ExpTime)).Unix()
	token, err := jwtToken.GenToken(userdata, t.TokenSignKey, Expired)
	if err != nil {
		g.Log().Error(r.GetCtx(), "生成TOKEN错误 ", err.Error())
		t.LoginLastHandler(r, jwtToken.AuthFail("生成TOKEN失败"))
	} else {
		t.LoginLastHandler(r, jwtToken.Succ(g.Map{"data": userdata, "token": token, "tokenExp": Expired}))
	}
}
func (t *Token) Logout(r *ghttp.Request) {
	t.LogoutHandler(r)
}

//授权验证
func (t *Token) authMiddleware(r *ghttp.Request) {
	//判断是否为登录页、静态文件、不拦截页
	urlPath := r.URL.Path
	if urlPath == "" || r.IsFileRequest() {
		r.Middleware.Next()
		return
	}
	res := t.getRequestToken(r)
	if res.Succ() {
		//有TOKEN 进行验证
		res = t.validToken(r, res.DataStrig())

	}

	t.AuthAfterHandler(r, res)
}

//验证TOKEN 判断是否快过期，如果快过期则生成新TOKEN 并将旧TOKEN缓存起来
func (t *Token) validToken(r *ghttp.Request, tokenString string) jwtToken.Resp {
	//var cailsm TokenClaims
	claims, err := jwtToken.VaildToken(tokenString, t.TokenSignKey)
	if err != nil {
		return jwtToken.AuthFail(err.Error())
	}
	//if claims.ExpiresAt
	return jwtToken.SuccWithMsg(claims.Payload, "")
}
func (t *Token) getRequestToken(r *ghttp.Request) jwtToken.Resp {
	tokenName := t.TokenHeaderName
	token := r.Header.Get(tokenName)
	if token != "" {
		parts := strings.SplitN(token, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			g.Log().Warning(r.GetCtx(), "[Token]authHeader:"+tokenName+" get token key fail")
			return jwtToken.UnauthFail("get token key fail", "")
		} else if parts[1] == "" {
			g.Log().Warning(r.GetCtx(), "[Token]authHeader:"+tokenName+" get token fail")
			return jwtToken.UnauthFail("get token fail", "")
		}
		return jwtToken.Succ(parts[1])
	}
	token = r.Get(tokenName).String()
	if token == "" {
		return jwtToken.UnauthFail("Token 不存在", "")
	}
	return jwtToken.Succ(token)
}

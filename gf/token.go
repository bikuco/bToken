package gf

import (
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
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
	LoginLastHandler   func(r *ghttp.Request, respData Resp)
	LogoutPath         string
	LogoutHandler      func(r *ghttp.Request)
	AuthAfterHandler   func(r *ghttp.Request, respData Resp)

	RefreshAfterHandler func(r *ghttp.Request, respData Resp) //刷新后操作
}

type TokenClaims struct {
	Payload interface{}
	jwt.StandardClaims
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
	mySigningKey := []byte(t.TokenSignKey)
	Expired := time.Now().Add(time.Hour * time.Duration(t.ExpTime)).Unix()
	claims := TokenClaims{
		userdata,
		jwt.StandardClaims{
			ExpiresAt: Expired,
		},
	}
	tokenCliaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err := tokenCliaims.SignedString(mySigningKey)
	if err != nil {
		g.Log().Error(r.GetCtx(), "生成TOKEN错误 ", err.Error())
		t.LoginLastHandler(r, AuthFail("生成TOKEN失败"))
	} else {
		t.LoginLastHandler(r, Succ(g.Map{"data": userdata, "token": token, "tokenExp": Expired}))
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
func (t *Token) validToken(r *ghttp.Request, tokenString string) Resp {
	//var cailsm TokenClaims
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(t.TokenSignKey), nil
	})
	if err != nil {
		return AuthFail("Token Is fail")
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return AuthFail("解析失败")
	}
	if err := token.Claims.Valid(); err != nil {
		return AuthFail(err.Error())
	}
	newtoken := ""
	if claims.ExpiresAt < 10 {
		//快过期生成新TOKEN 先判断之前是否生成过新的TOKEN如果生成有则直接获取，如果没有则生成
		newtoken = tokenString
		r.Header.Set(t.RefreshHeaderName, newtoken)                     //响应头返回新的token
		t.RefreshAfterHandler(r, SuccWithMsg(claims.Payload, newtoken)) //调用刷新后操作
	}

	return SuccWithMsg(claims.Payload, newtoken)
}
func (t *Token) getRequestToken(r *ghttp.Request) Resp {
	tokenName := t.TokenHeaderName
	token := r.Header.Get(tokenName)
	if token != "" {
		parts := strings.SplitN(token, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			g.Log().Warning(r.GetCtx(), "[Token]authHeader:"+tokenName+" get token key fail")
			return UnauthFail("get token key fail", "")
		} else if parts[1] == "" {
			g.Log().Warning(r.GetCtx(), "[Token]authHeader:"+tokenName+" get token fail")
			return UnauthFail("get token fail", "")
		}
		return Succ(parts[1])
	}
	token = r.Get(tokenName).String()
	if token == "" {
		return UnauthFail("Token 不存在", "")
	}
	return Succ(token)
}

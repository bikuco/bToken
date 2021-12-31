package gfToken

import "github.com/gogf/gf/v2/net/ghttp"

func (t *Token) Enable(group ghttp.RouterGroup) error {
	t.InitConfig()
	group.Middleware(t.authMiddleware)
	group.POST(t.LoginPath, t.Login)
	group.GET(t.LogoutPath, t.Logout)
	return nil
}

package jwt

import (
	"errors"

	"github.com/dgrijalva/jwt-go"
)

type TokenClaims struct {
	Payload            interface{} `json:"payload"`
	jwt.StandardClaims `json:"claims"`
}

func GenToken(data interface{}, signKey string, expired int64) (string, error) {
	mySigningKey := []byte(signKey)

	claims := TokenClaims{
		data,
		jwt.StandardClaims{
			ExpiresAt: expired,
		},
	}
	tokenCliaims := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tokenCliaims.SignedString(mySigningKey)
}
func VaildToken(tokenString string, signKey string) (*TokenClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(signKey), nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, errors.New("解析失败")
	}
	if err := token.Claims.Valid(); err != nil {
		return nil, err
	}
	return claims, nil
	/*
		newtoken := ""
		if claims.ExpiresAt < 10 {
			//快过期生成新TOKEN 先判断之前是否生成过新的TOKEN如果生成有则直接获取，如果没有则生成
			newtoken = tokenString
			r.Header.Set(t.RefreshHeaderName, newtoken)                     //响应头返回新的token
			t.RefreshAfterHandler(r, SuccWithMsg(claims.Payload, newtoken)) //调用刷新后操作
		}
	*/
}

func BackToken(tokenString string) {}

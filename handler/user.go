package handler

import (
	"LearnScheduleSystemWithGoLang/config"
	"LearnScheduleSystemWithGoLang/pkg/jwt"
	"LearnScheduleSystemWithGoLang/pkg/res"

	"github.com/gin-gonic/gin"
)

// GetUserInfo GetUserInfo
func GetUserInfo(c *gin.Context) {
	token, err := c.Cookie(jwt.Key)
	if err != nil {
		res.Success(c, gin.H{
			"is_login":  false,
			"user_name": "",
			"user_id":   "",
		})
		return
	}

	id, name, err := jwt.ParseToken(token)
	if err != nil {
		res.Success(c, gin.H{
			"is_login":  false,
			"user_name": "",
			"user_id":   "",
		})
		return
	}

	res.Success(c, gin.H{
		"is_login":  true,
		"user_name": name,
		"user_id":   id,
	})
}

// GetUserLogout GetUserLogout
func GetUserLogout(c *gin.Context) {
	c.SetCookie(jwt.Key, "", -1, "/", config.Val.Domain, false, true)

	res.Success(c, gin.H{})
}

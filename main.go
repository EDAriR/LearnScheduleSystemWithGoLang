package main

import (
	"LearnScheduleSystemWithGoLang/config"
	"LearnScheduleSystemWithGoLang/handler"
	"LearnScheduleSystemWithGoLang/middleware"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func main() {
	load()

	gin.SetMode(config.Val.Mode)
	r := gin.Default()
	r.Use(middleware.CROSS())

	r.GET("/ping", handler.Ping)

	api := r.Group("/api")
	{
		api.GET("ouath/google/url", handler.GoogleAccsess)
		api.GET("ouath/google/login", handler.GoogleLogin)
		api.GET("user/info", handler.GetUserInfo)
		api.GET("user/logout", handler.GetUserLogout)

		// TODO
		// api.GET("user/logout", middleware.Auth(), handler.GetUserLogout)

		api.POST("/task", middleware.Auth(), handler.CreateTask)
		// api.GET("groups", middleware.Auth(), handler.GetGroups)
		api.GET("groups", handler.GetGroups)
		//

	}

	r.Run(":" + config.Val.Port)

	log.Infof("serve port: %v \n", config.Val.Port)
}

func load() {
	config.Init()
}

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
	}

	r.Run(":" + config.Val.Port)

	log.Infof("serve port: %v \n", config.Val.Port)
}

func load() {
	config.Init()
}

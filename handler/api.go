package handler

import (
	"LearnScheduleSystemWithGoLang/config"
	"LearnScheduleSystemWithGoLang/model"
	"LearnScheduleSystemWithGoLang/pkg/jwt"
	"LearnScheduleSystemWithGoLang/pkg/redis"
	"LearnScheduleSystemWithGoLang/pkg/res"
	"context"
	"encoding/json"
	"time"

	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// Ping Ping
func Ping(c *gin.Context) {
	res.Success(c, gin.H{
		"msg": "pong",
	})
}

// GoogleAccsess GoogleAccsess
func GoogleAccsess(c *gin.Context) {
	res.Success(c, gin.H{
		"url": oauthURL(),
	})
}

const scope = "https://www.googleapis.com/auth/userinfo.profile" // (授權使用者資料)

func oauthURL() string {
	u := "https://accounts.google.com/o/oauth2/v2/auth?client_id=%s&response_type=code&scope=%s&redirect_uri=%s"

	return fmt.Sprintf(u, config.Val.GoogleClientID, scope, config.Val.RedirectURL)
}

// GoogleLogin GoogleLogin
func GoogleLogin(c *gin.Context) {
	code := c.Query("code")

	token, err := accessToken(code)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("accessToken error")
		c.Redirect(http.StatusFound, "/")
		return
	}

	id, name, err := getGoogleUserInfo(token)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("getGoogleUserInfo error")
		c.Redirect(http.StatusFound, "/")
		return
	}

	jwtToken, err := jwt.GenerateToken(id, name)
	if err != nil {
		log.WithFields(log.Fields{
			"err": err,
		}).Debug("GenerateToken error")
		c.Redirect(http.StatusFound, "/")
		return
	}

	c.SetCookie(jwt.Key, jwtToken, config.Val.JWTTokenLife, "/", "localhost", false, true)

	// 把值log出來看
	log.Infof("id: %v, name: %v", id, name)
}

func accessToken(code string) (token string, err error) {
	u := "https://www.googleapis.com/oauth2/v4/token"

	data := url.Values{
		"code":          {code},
		"client_id":     {config.Val.GoogleClientID},
		"client_secret": {config.Val.GoogleSecretKey},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {config.Val.RedirectURL},
	}

	body := strings.NewReader(data.Encode())

	resp, err := http.Post(u, "application/x-www-form-urlencoded", body)
	if err != nil {
		return token, err
	}

	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return token, err
	}

	token = gjson.GetBytes(b, "access_token").String()

	return token, nil
}

func getGoogleUserInfo(token string) (id, name string, err error) {
	u := fmt.Sprintf("https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token=%s", token)
	resp, err := http.Get(u)
	if err != nil {
		return id, name, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return id, name, err
	}

	name = gjson.GetBytes(body, "name").String()
	id = gjson.GetBytes(body, "id").String()

	return id, name, nil
}

// CreateTask CreateTask
func CreateTask(c *gin.Context) {
	var taskData model.Task
	c.BindJSON(&taskData)

	taskData.UserID = c.GetString("user_id")
	taskData.Status = model.TaskAble
	taskData.CreatedTimestamp = time.Now().UTC().Unix()

	if err := model.TaskModel.Create(taskData); err != nil {
		log.WithFields(log.Fields{
			"task_data":  taskData,
			"origin_err": err.Error(),
		}).Error("db error")
		res.SystemError(c, res.ErrSystemCode, gin.H{})
		return
	}

	res.Success(c, gin.H{})
}

type GroupsList struct {
	ID    int           `json:"id"`
	Name  string        `json:"name"`
	Tasks []*model.Task `json:"tasks"`
}

func GetGroups(c *gin.Context) {
	userID := c.GetString("user_id")

	var groupList []*GroupsList
	groups, tasks, err := findGroupsAndTasks(userID)
	if err != nil {
		log.WithFields(log.Fields{
			"user_id":    userID,
			"origin_err": err.Error(),
		}).Error("findGroup error")
		res.SystemError(c, res.ErrSystemCode, gin.H{})
		return
	}

	for _, p := range groups {
		groupList = append(groupList, &GroupsList{
			ID:   p.ID,
			Name: p.Name,
		})
	}

	for _, t := range tasks {
		if t.Status != model.TaskAble {
			continue
		}

		for _, g := range groupList {
			if t.ParentID == g.ID {
				g.Tasks = append(g.Tasks, t)
				break
			}
		}
	}

	res.Success(c, gin.H{
		"groups": groupList,
	})
}

func findGroupsAndTasks(userID string) (groups []*model.Task, tasks []*model.Task, err error) {
	groups, err = findGroups(userID)
	if err != nil {
		return
	}

	parentID := []int{}
	for _, p := range groups {
		parentID = append(parentID, p.ID)
	}

	tasks, err = findTasks(userID, parentID)
	if err != nil {
		return
	}

	return
}

func redisGroupsKey(userID string) string {
	return "groups:" + userID
}

func redisTasksKey(userID string) string {
	return "tasks:" + userID
}

func findGroups(userID string) (groups []*model.Task, err error) {
	val, err := redis.Conn.Get(context.Background(), redisGroupsKey(userID)).Bytes()
	if err == nil {
		if err = json.Unmarshal(val, &groups); err == nil {
			return
		}
	}

	groups, err = model.TaskModel.GetGroup(userID)
	if err != nil {
		return
	}

	groupsJSON, _ := json.Marshal(groups)
	redis.Conn.Set(context.Background(), redisGroupsKey(userID), groupsJSON, 24*3*time.Hour)

	return
}

func findTasks(userID string, parentID []int) (tasks []*model.Task, err error) {
	var data []*model.Task
	redisCache := false
	val, err := redis.Conn.Get(context.Background(), redisTasksKey(userID)).Bytes()
	if err == nil {
		if err = json.Unmarshal(val, &data); err == nil {
			redisCache = true
		}
	}

	if len(data) == 0 {
		data, err = model.TaskModel.GetTasks(userID, []int{model.TaskAble, model.TaskDone})
		if err != nil {
			return
		}
	}

	if !redisCache {
		tasksJSON, _ := json.Marshal(data)
		redis.Conn.Set(context.Background(), redisTasksKey(userID), tasksJSON, 24*3*time.Hour)
	}

	for _, t := range data {
		for _, pid := range parentID {
			if pid == t.ParentID {
				tasks = append(tasks, t)
				break
			}
		}
	}

	return
}

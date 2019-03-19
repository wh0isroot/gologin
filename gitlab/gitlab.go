package gitlab

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/Sirupsen/logrus"
	"golang.org/x/oauth2"
)

//Config has base config for gitlab oauth
type Config struct {
	gitlabAddress string
	oauthConfig   oauth2.Config
}

//User has gitlab user api return elements
type User struct {
	ID        int    `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	State     string `json:"state"`
	AvatarURL string `json:"avatar_url"`
	WebURL    string `json:"web_url"`
}

const gitlabUserAPI = "/api/v4/user"

//NewOauthGitlab creat a new OauthGitlab instance
func NewOauthGitlab(gitlabAddress string, authURL string, tokenURL, clientID string, clientSecret string, redirectURL string, scopes []string) *Config {
	endpoint := &oauth2.Endpoint{
		AuthURL:  authURL,
		TokenURL: tokenURL,
	}

	config := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     *endpoint,
		RedirectURL:  redirectURL,
		Scopes:       scopes,
	}

	o := &Config{
		gitlabAddress: gitlabAddress,
		oauthConfig:   *config,
	}
	return o
}

//NewAuthCodeURL create a new url redirect to get a auth code
func (o *Config) NewAuthCodeURL(state string) string {
	return o.oauthConfig.AuthCodeURL(state)
}

//CallBack return a token which has user capability
func (o *Config) CallBack(code string) (*User, error) {
	token, err := o.oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		logrus.Errorf("gitlab code exchange failed with '%v'\n", err)
		return nil, err
	}
	u, err := o.GetUserInfo(token)
	if err != nil {
		logrus.Errorf("gitlab get userinfo failed with '%v'\n", err)
		return nil, err
	}
	return u, nil

}

//GetUserInfo retun GitlabUser
func (o *Config) GetUserInfo(token *oauth2.Token) (*User, error) {
	url := o.gitlabAddress + gitlabUserAPI
	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("gitlab oauth req err: %v\n", err)
		return nil, err
	}
	if resp.StatusCode != 200 {
		logrus.Infof("gitlab oauth permission deny: %v\n", *token)
		return nil, nil
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logrus.Errorf("gitlab oauth read contents err: %v\n", err)
		return nil, err
	}
	user := new(User)
	err = json.Unmarshal(contents, user)
	if err != nil {
		logrus.Errorf("gitlab oauth wrong json: %v", err)
		return nil, err
	}
	return user, nil

}

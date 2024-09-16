package main

import (
	"flag"
	db "github.com/matelq/GoAuth/database"
	"github.com/matelq/GoAuth/auth"
	log "github.com/sirupsen/logrus"
	"github.com/matelq/GoAuth/mockmail"
)

func main() {

	var port string
	var secret string
	var access int
	var refresh int
	flag.StringVar(&port, "port", "12345", "Specify server port. Default is \"12345\".")
	flag.StringVar(&secret, "secret", "secret", "Specify secret for signing tokens. Default is \"secret\".")
	flag.IntVar(&access, "access_lifetime", 300, "Specify server access token lifetime. Default is \"300\".")
	flag.IntVar(&refresh, "refresh_lifetime", 60000, "Specify server refresh token lifetime. Default is \"60000\".")
	flag.Parse()
	
	dbConn := "postgres://postgres:pswd@127.0.0.1:5432/GoAuth"
	db.Init(dbConn)
	mockmail.Init("example@mail.from", "some smtp auth credentials")
	auth.StartServer(port, secret, access, refresh)
	log.Info("Server started")

}

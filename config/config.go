package config

import (
	"log"
	"path/filepath"
	"github.com/spf13/viper"
)

var config *viper.Viper

// Init is an exported method that takes the environment starts the viper
// (external lib) and returns the configuration struct.
func Init(env string) {
	var err error
	config = viper.New()
	config.SetConfigType("yaml")
	config.SetConfigName(env)
	config.AddConfigPath("../config/")
	config.AddConfigPath("config/")
	config.AddConfigPath("src/config/")
	err = config.ReadInConfig()
	if err != nil {
		log.Fatalf("error on parsing configuration file %s", err)
	}
}

func relativePath(basedir string, path *string) {
	p := *path
	if len(p) > 0 && p[0] != '/' {
		*path = filepath.Join(basedir, p)
	}
}

// Function GetConfig
func GetConfig() *viper.Viper {
	return config
}

// Function GetSecretKey
func GetSecretKey() string {
	configs := GetConfig()
	key := configs.GetString("security.secret_key")
	return key
}

// Function GetHost
func GetHost() string {
	configs := GetConfig()
	host := configs.GetString("server.host")
	return host
}

// Function GetPort
func GetPort() string {
	configs := GetConfig()
	port := configs.GetString("server.port")
	return port
}

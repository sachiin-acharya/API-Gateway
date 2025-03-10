// go_gateway/internal/config/config.go

// Package config le application configuration manage garcha
package config

import (
	"strings"
	//strings le string manipulation function provide garcha

	"github.com/spf13/viper"
	//viper chai go ko configuration solution ho, yo chai similar to python ko os.environ
)

// Config struct le purai application ko configuration hold garcha

// mapstructure chai go ko package ho jasle chai dictionary like structure(map) lai struct ma decode gardincha
type Config struct {
	Server struct {
		Port                string `mapstructure:"port"`                  //HTTP Port to listen on
		ReadTimeoutSeconds  int    `mapstructure:"read_timeout_seconds"`  //Timeout for reading requests
		WriteTimeoutSeconds int    `mapstructure:"write_timeout_seconds"` //Timeout for writing responses
		IdleTimeoutSeconds  int    `mapstructure:"idle_timeout_seconds"`  //Timeout for idle connections
	} `mapstructure:"server"`

	// Yo chai services configuration section ho
	// Yesma hamro application le communicate garne external services haru ko settings cha
	Services struct {
		// Auth chai authentication server ko lagi
		Auth struct {
			URL     string `mapstructure:"url"`
			Timeout int    `mapstructure:"timeout_seconds"`
		} `mapstructure:"auth"`
		// Main chai main backend ko lagi
		Main struct {
			URL     string `mapstructure:"url"`
			Timeout int    `mapstructure:"timeout_seconds"`
		} `mapstructure:"main"`
		// Notification chai notification server ko lagi
		Notification struct {
			URL     string `mapstructure:"url"`
			Timeout int    `mapstructure:"timeout_seconds"`
		} `mapstructure:"notification"`
	} `mapstructure:"services"`

	// Authentication configuration section, yo chai hamro gateway ko internal authentication ko lagi ho
	Auth struct {
		JWTSecret            string `mapstructure:"jwt_secret"`
		AccessTokenDuration  int    `mapstructure:"access_token_duration_minutes"`
		RefreshTokenDuration int    `mapstructure:"refresh_token_duration_days"`
	} `mapstructure:"auth"`

	// Redis configuration section, yes vitra redis ko server address, server password ra database index cha
	Redis struct {
		Address  string `mapstructure:"address"`
		Password string `mapstructure:"password"`
		DB       int    `mapstructure:"db"`
	} `mapstructure:"redis"`

	// Ratelimit configuration section, it contains settings such as rate limiting enable cha ki chaena, rate limit per minute ra
	// number of request jo chai rate limit vanda mathi jana diney
	RateLimit struct {
		Enabled bool `mapstructure:"enabled"`
		Limit   int  `mapstructure:"limit"`
		Burst   int  `mapstructure:"burst"`
	} `mapstructure:"rate_limit"`

	// Tracing is used for monitoring and debugging distributed applications by tracking flow of requests
	// across different services. Used to identify bottlenecks.
	// Jaegar endpoint le chai yesto URL define garcha jasma data pathaunu parcha
	Tracing struct {
		Enabled        bool   `mapstructure:"enabled"`
		JaegerEndpoint string `mapstructure:"jaeger_endpoint"`
	} `mapstructure:"tracing"`

	// Yo ta logging vai halyo
	Logging struct {
		Level string `mapstructure:"level"`
		JSON  bool   `mapstructure:"json"`
	} `mapstructure:"logging"`
}

// Load le just file ra environment variable bata configuration read garcha
// Yo function le Config struct ma pointer ra error return garcha
func Load() (*Config, error) {

	// Configure viper to look for config files
	viper.SetConfigName("config")    // Name of config file without extension
	viper.SetConfigType("yaml")      // Type of config file
	viper.AddConfigPath("./configs") // First path to look for the config file
	viper.AddConfigPath(".")         // Second path to look for config file

	// Enable reading from environment variables
	viper.AutomaticEnv()

	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	//Set Defaults
	viper.SetDefault("server.port", "8080")
	viper.SetDefault("server.read_timeout_seconds", 10)
	viper.SetDefault("server.write_timeout_seconds", 10)
	viper.SetDefault("server.idle_timeout_seconds", 120)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.json", true)
	viper.SetDefault("rate_limit.enabled", true)
	viper.SetDefault("rate_limit.limit", 100)
	viper.SetDefault("rate_limit.burst", 50)

	// Try to read the config file
	// If it doesn't exist, we'll use environment variables and defaults
	if err := viper.ReadInConfig(); err != nil {
		// Check if the error is that the config file wasn't found
		// This is acceptable, as we can use environment variables and defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			// If it's some other error, return it
			return nil, err
		}
		// If the config file wasn't found, we just continue with defaults and env vars
	}

	// Create a new Config struct
	var cfg Config

	// Populate the Config struct from viper's values
	// This is similar to parsing config in Python and creating an object
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Return the populated Config struct
	return &cfg, nil
}

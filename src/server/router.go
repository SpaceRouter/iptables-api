package server

import (
	"github.com/gin-gonic/gin"
	cors "github.com/itsjamie/gin-cors"
	"github.com/spacerouter/sr_auth"
	"iptables-api/config"
	"iptables-api/controllers"
	"log"
)

func NewRouter(savePath string) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	router.Use(cors.Middleware(cors.Config{
		Origins:         "*",
		Methods:         "GET, PUT, POST, DELETE",
		RequestHeaders:  "Origin, Authorization, Content-Type",
		ExposedHeaders:  "",
		Credentials:     true,
		ValidateHeaders: false,
	}))

	auth := sr_auth.CreateAuth(config.GetSecretKey(), config.GetAuthServer(), nil)
	err := auth.PingAuthServer()
	if err != nil {
		log.Fatal(err)
	}

	main := router.Group("firewall")
	{

		main.Use(auth.SrAuthMiddlewareGin())

		s := controllers.SaveStruct{SavePath: savePath}

		rules := main.Group("rules")
		{
			rules.PUT(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.AddRules)
			rules.DELETE(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.DelRules)
			rules.GET(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.CheckRules)
		}

		raw := main.Group("raw")
		{
			raw.PUT(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.AddRaw)
			raw.DELETE(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.DelRaw)
			raw.GET(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.CheckRaw)
		}

		nat := main.Group("nat")
		{
			nat.PUT(":action/:chain/:proto/:iface/:source/:destination/:nat_final/", controllers.AddNat)
			nat.DELETE(":action/:chain/:proto/:iface/:source/:destination/:nat_final/", controllers.DelNat)
			nat.GET(":action/:chain/:proto/:iface/:source/:destination/:nat_final/", controllers.CheckNat)
		}

		chain := main.Group("chain")
		{
			chain.PUT(":table/:name/", controllers.AddChain)
			chain.DELETE(":table/:name/", controllers.DelChain)
			chain.GET(":table/:name/", controllers.ListChain)
		}

		main.PUT("mvchain/:table/:oldname/:newname/", controllers.RenameChain)

		/*
			rulesV6 := main.Group("rules_v6")
			{
				rulesV6.PUT(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.AddRulesV6)
				rulesV6.DELETE(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.DelRulesV6)
				rulesV6.GET(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.CheckRulesV6)
			}

			rawV6 := main.Group("raw_v6")
			{
				rawV6.PUT(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.AddRawV6)
				rawV6.DELETE(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.DelRawV6)
				rawV6.GET(":action/:chain/:proto/:iface_in/:iface_out/:source/:destination/", controllers.CheckRawV6)
			}

			natV6 := main.Group("nat_v6")
			{
				natV6.PUT(":action/:chain/:proto/:iface/:source/:destination/:nat_final/", controllers.AddNatV6)
				natV6.DELETE(":action/:chain/:proto/:iface/:source/:destination/:nat_final/", controllers.DelNatV6)
				natV6.GET(":action/:chain/:proto/:iface/:source/:destination/:nat_final/", controllers.CheckNatV6)
			}

			chainV6 := main.Group("chain_v6")
			{
				chainV6.PUT(":table/:name/", controllers.AddChainV6)
				chainV6.DELETE(":table/:name/", controllers.DelChainV6)
				chainV6.GET(":table/:name/", controllers.ListChainV6)
			}

			main.PUT("mvchain_v6/:table/:oldname/:newname/", controllers.RenameChainV6)

			main.GET("save_v6", s.SaveRulesV6)
			main.GET("restore_v6", controllers.RestoreRulesV6)
		*/
		main.GET("save", s.SaveRules)
		main.GET("restore", controllers.RestoreRules)
	}
	return router

}

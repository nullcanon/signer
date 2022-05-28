package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"signer"
	"signer/config"

	"github.com/ethereum/go-ethereum/rpc"
)

func main() {
	var s = flag.String("p", "../config/server.toml", "config file path, ex : ../config/server.toml")
	flag.Parse()

	var cfg config.Config
	if err := config.LoadConfig(*s, &cfg); err != nil {
		fmt.Printf("load conf error:%s\n", err.Error())
		os.Exit(1)
	}

	file, err := os.OpenFile(cfg.Log.Filename, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if err != nil {
		fmt.Printf("error opening file: %v", err)
		os.Exit(1)
	}
	logger := log.New(file, "applog", log.Lshortfile|log.Ldate|log.Lmicroseconds)

	rpcAPI := []rpc.API{
		{
			Namespace: "signer",
			Version:   "1.0",
			Service:   signer.NewSignerService(logger),
			Public:    true,
		},
	}

	httpSrv := signer.NewServer(rpcAPI, &cfg, logger, signer.HTTP)
	httpSrv.Start()
	defer httpSrv.Stop()

	ch := make(chan bool)
	<-ch
}

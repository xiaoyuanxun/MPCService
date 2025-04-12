package main

import (
	"log"
	"os"

	"github.com/urfave/cli"
	"github.com/xiaoyuanxun/MPCService/cmd"
)

// main runs the CLI app.
func main() {
	app := cli.NewApp()
	app.Name = "MPC service"
	app.Usage = `A CLI app for running the MPC service`
	app.Commands = []cli.Command{cmd.MpcNodeCmd, cmd.ManagerCmd, cmd.DataProviderCMD}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

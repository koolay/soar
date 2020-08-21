package main

import (
	"encoding/json"
	"fmt"

	"github.com/XiaoMi/soar/run"
)

func main() {
	sql := "select * from tab"
	output, err := run.Run(sql)
	if err != nil {
		panic(err)
	}

	data, _ := json.Marshal(output)
	fmt.Printf("%+v", data)
}

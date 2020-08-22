package main

import (
	"fmt"

	"github.com/XiaoMi/soar/run"
)

func main() {
	sql := "select t1.* from tab t1 inner join tb2 as t2 on t1.id = t2.fid"
	output, err := run.Run(sql, 7)
	if err != nil {
		panic(err)
	}

	fmt.Printf("%+v", output)
}

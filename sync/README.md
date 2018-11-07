# sync for go

``` go
package main

import (
    "go-tool/sync"
    "log"
)

func main() {
    // the first way
    connection := sync.CONNECTION{
        Host: "127.0.0.1",
        Port: 22,
        User: "username",
        Pass: "password",
    }
    path := sync.PATH{
        Local:  "home/root",
        Remote: "/home/root/test",
    }
    node := sync.NODE{
        Connection: connection,
        Path:       path,
    }
    cli := sync.CLISHOW{
        Unchange:  true,
        Change:    true,
        Ignore:    true,
        Spendtime: true,
        Print:     true,
    }
    ignore := []string{".git", "public/Runtime/", "public/Runtime/!Temp"}
    obj := sync.SYNC{
        Node:   node,
        Ignore: ignore,
        Cli:    cli,
    }
    obj.DoSyncCli() // obj.DoSync()

    // the second way
    obj, err := sync.InitByFile("~/conf.yaml")
    if err != nil {
        log.Fatalln(err)
    }
    obj.DoSyncCli() // obj.DoSync()

    // the third way
    yy := `
node:
  connection:
    host: 127.0.0.1  # ip address
    port: 22 # ssh port
    user: username # username
    pass: password # password
  path:
    local: /home/root/test # local path 
    remote: /home/root/test # remote path

ignore: [".git", "public/Runtime/Logs/", "public/Runtime/!Temp",  "/public/*.js"] # ignore file

cli:
  unchange: true # if show unchange file 
  change: true # if show change file
  ignore: true # if show ignore file
  spendtime: true # if show spend time
  print: true # if print summary
`
    obj, err := sync.InitByYaml([]byte(yy))
    if err != nil {
        log.Fatalln(err)
    }
    obj.DoSyncCli() // obj.DoSync()
}
```
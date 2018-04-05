package main

import (
//  "net"
//  cssh "golang.org/x/crypto/ssh"
//  "bufio"
    "encoding/json"
    "log"
    "github.com/gliderlabs/ssh"
    "strings"
    "io/ioutil"
    "io"
    "fmt"
    "os"
    "regexp"
)

func search_key(device string,keyfile string) (string,bool) {
    re_clean:=regexp.MustCompile("([a-f0-9]{1,3}:){5}[a-f0-9]{1,3}")
    re_pass:=regexp.MustCompile("[^|]+$")
    re_mac:=regexp.MustCompile("^[^|]+")
    file,e:=ioutil.ReadFile(keyfile)
    if e != nil{
        panic(e)
    }
    flines:=strings.Split(string(file),"\n")
    flines=flines[:len(flines)-1]
    devs:=re_clean.FindAllString(strings.ToLower(device),-1)
    if devs==nil{return "",false}
    for _,dev:=range devs{
        for _,l:= range flines{
            //log.Printf("%s: %s=>%s\n",dev,l,re_pass.FindString(l))
            if re_mac.FindString(l)==dev{return re_pass.FindString(l), true}
        }
    }
    return "",false
}
type Config struct{
    Addr string
    Port int
    Cryptkeys string
    Host_id string
    Authorized_keys string
}
func parse_options() (Config){
    config:= Config{}
    configfile,e:= os.Open(os.Args[1])
    defer configfile.Close()
    if e !=nil{log.Fatal(e)}
    dec:=json.NewDecoder(configfile)
    e= dec.Decode(&config)
    if e!=nil{
	log.Fatal(e)
    }
    return config
}
func main(){
    conf:=parse_options()
    keys:=make([]ssh.PublicKey,0)
    file,_:=ioutil.ReadFile(conf.Authorized_keys)
    for pkey,_,_,rest,e:=ssh.ParseAuthorizedKey(file);e==nil; pkey,_,_,rest,e=ssh.ParseAuthorizedKey(rest){
        keys=append(keys,pkey)
    }
    ssh.Handle(func(session ssh.Session){
        dev:=session.RemoteAddr()
        if mes:=session.Command();len(mes)>=1{
            p,a:=search_key(mes[0],conf.Cryptkeys)
            if a{
                log.Printf("cryptobox: %s: \"%s\"=> %s\n",dev,mes[0],p)
                io.WriteString(session,p)
            }else{log.Printf("cryptobox: %s: \"%s\" has no key...\n",dev,mes[0])}
        }else{log.Printf("cryptobox: %s: wrong format...\n",dev)}
    })
    pubkey_opt:=ssh.PublicKeyAuth(func(con ssh.Context, pkey ssh.PublicKey) bool{
        is_valid:=false
        for _,key:= range keys{
            if ssh.KeysEqual(pkey,key){is_valid=true}
        }
        return is_valid
    })
    log.Fatal(ssh.ListenAndServe(fmt.Sprintf("%s:%d",conf.Addr,conf.Port), nil, ssh.HostKeyFile(conf.Host_id),pubkey_opt))
}

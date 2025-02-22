package sshtunnel

import (
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
	"io"
	"log"
	"math"
	"net"
	"strings"
	"syscall"
	"time"
)

type SSHTunnel struct {
	config *Config
	client *ssh.Client
}

func NewSSHTunnel(config *Config) *SSHTunnel {
	st := new(SSHTunnel)
	st.config = config
	return st
}

func (st *SSHTunnel) Start() {
	if len(st.config.Pass) == 0 {
		st.setPass()
	}
	st.initSSHClient()
	for _, t := range st.config.Tunnels {
		go st.connect(t)
	}
}

func (st *SSHTunnel) Close() {
	if nil != st.client {
		st.client.Close()
	}
}


func (st *SSHTunnel) GetSSHClient() (*ssh.Client, error) {
	if st.client != nil {
		return st.client, nil
	}
	var auth []ssh.AuthMethod
	auth = make([]ssh.AuthMethod, 0)

	// 如果配置中有密钥字符串，使用密钥认证
	if st.config.Key != "" {
		//fmt.Println(st.config.Key)
		if st.config.KeyPass != "" {
			// 使用 passphrase 解密密钥字符串
			passphrase := "admin" // 提供密码来解密密钥
			// 解析加密的密钥字符串
			signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(st.config.Key), []byte(passphrase))
			if err != nil {
				return nil, fmt.Errorf("解析私钥失败: %v", err)
			}
			auth = append(auth, ssh.PublicKeys(signer))
		} else {
			//signer, err := ssh.ParsePrivateKeyWithPassphrase([]byte(st.config.Key), []byte(passphrase))
			//if err != nil {
			//	return nil, fmt.Errorf("解析私钥失败: %v", err)
			//}

			// 解析密钥字符串
			signer, err := ssh.ParsePrivateKey([]byte(st.config.Key))
			if err != nil {
				return nil, fmt.Errorf("解析私钥失败: %v", err)
			}

			auth = append(auth, ssh.PublicKeys(signer))
		}
	} else {
		// 否则使用密码认证
		auth = append(auth, ssh.Password(st.config.Pass))
	}

	// 创建 SSH 客户端配置
	sc := &ssh.ClientConfig{
		User: st.config.User,
		Auth: auth,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	// 尝试连接 SSH 服务器
	var err error
	st.client, err = ssh.Dial("tcp", st.config.Addr, sc)
	if err != nil {
		return nil, err
	}

	log.Printf("连接到服务器成功: %s", st.config.Addr)
	return st.client, nil
}


// func (st *SSHTunnel) GetSSHClient() (*ssh.Client, error) {
// 	if st.client != nil {
// 		return st.client, nil
// 	}
// 	var auth []ssh.AuthMethod
// 	auth = make([]ssh.AuthMethod, 0)
// 	auth = append(auth, ssh.Password(st.config.Pass))

// 	sc := &ssh.ClientConfig{
// 		User: st.config.User,
// 		Auth: auth,
// 		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
// 			return nil
// 		},
// 	}
// 	var err error
// 	st.client, err = ssh.Dial("tcp", st.config.Addr, sc)
// 	if err != nil {
// 		return nil, err
// 	}
// 	log.Printf("连接到服务器成功: %s", st.config.Addr)
// 	return st.client, err
// }

func (st *SSHTunnel) connect(t Tunnel) {
	tid := fmt.Sprintf("%s-%s", t.Local, t.Remote)
	ll, err := net.Listen("tcp", t.Local)
	if err != nil {
		log.Printf("隧道[%s]接收开启失败, 错误: %v", tid, err)
		return
	}
	defer func() {
		ll.Close()
		log.Printf("隧道[%s]接收关闭!", tid)
	}()
	log.Printf("隧道[%s]接收开启!", tid)
	sno := int64(0)
	for {
		lc, err := ll.Accept()
		if err != nil {
			log.Printf("隧道[%s]接收连接失败, 错误: %v", tid, err)
			return
		}
		sc, err := st.GetSSHClient()
		if err != nil {
			log.Printf("隧道[%s]接入服务失败, 错误: %v", tid, err)
			lc.Close()
			continue
		}
		rc, err := sc.Dial("tcp", t.Remote)
		if err != nil {
			log.Printf("隧道[%s]接入获取连接失败, 错误: %v", tid, err)
			sc.Close()
			lc.Close()
			continue
		}
		if sno >= math.MaxInt64 {
			sno = 0
		}
		sno += 1
		cid := fmt.Sprintf("%s:%d", tid, sno)
		go st.transfer(cid, lc, rc)
	}
}

func (st *SSHTunnel) setPass() {
	fmt.Printf("请输入登陆密码[%s@%s]:", st.config.User, st.config.Addr)
	bytePassword, _ := terminal.ReadPassword(int(syscall.Stdin))
	st.config.Pass = string(bytePassword)
	fmt.Println()
}

func (st *SSHTunnel) initSSHClient() {
	var err error
	for {
		st.client, err = st.GetSSHClient()
		if nil != err {
			error := err.Error()
			log.Printf("连接到服务器[%s]失败, 错误: %s", st.config.Addr, error)
			if strings.Contains(error, "unable to authenticate") {
				st.config.Pass = ""
				st.setPass()
				continue
			}
			if strings.Contains(error, "i/o timeout") {
				log.Printf("连接到服务器[%s]超时!", st.config.Addr)
				time.Sleep(2 * time.Second)
				continue
			}
		}
		return
	}
}

func (st *SSHTunnel) transfer(cid string, lc net.Conn, rc net.Conn) {
	defer rc.Close()
	defer lc.Close()
	go func() {
		defer lc.Close()
		defer rc.Close()
		io.Copy(rc, lc)
	}()
	log.Printf("通道[%s]已连接!", cid)
	io.Copy(lc, rc)
	log.Printf("通道[%s]已断开!", cid)
}

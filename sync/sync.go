package sync

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/go-yaml/yaml"
	"github.com/pkg/sftp"

	"golang.org/x/crypto/ssh"
)

var (
	ignore  []IGNORE
	force   []string
	summary SUMMARY
	isCli   bool
	object  *SYNC
)

type SYNC struct {
	Node   NODE     `yaml:"node"`
	Ignore []string `yaml:"ignore"`
	Cli    CLISHOW  `yaml:"cli"`
}

// SUMMARY summary
type SUMMARY struct {
	change    []string
	unchange  []string
	ignore    []string
	spendtime time.Duration
}

// IGNORE ignore file or director
type IGNORE struct {
	fix  bool
	file string
}

// CONNECTION yaml config
type CONNECTION struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	User string `yaml:"user"`
	Pass string `yaml:"pass"`
}

// PATH yaml config
type PATH struct {
	Local  string `yaml:"local"`
	Remote string `yaml:"remote"`
}

// NODE yaml config
type NODE struct {
	Connection CONNECTION `yaml:"connection"`
	Path       PATH       `yaml:"path"`
}

// CLISHOW show info in cli mode
type CLISHOW struct {
	Unchange  bool `yaml:"unchange"`
	Ignore    bool `yaml:"ignore"`
	Change    bool `yaml:"change"`
	Spendtime bool `yaml:"spendtime"`
	Print     bool `yaml:"print"`
}

func InitByYaml(config []byte) (*SYNC, error) {
	co := SYNC{}
	yaml.Unmarshal(config, &co)
	if co.Node == (NODE{}) {
		return nil, errors.New("load config fail")
	}
	return &co, nil
}

func InitByFile(configFile string) (*SYNC, error) {
	config, err := ioutil.ReadFile(configFile)
	co := SYNC{}
	if err != nil {
		return nil, err
	}
	yaml.Unmarshal(config, &co)
	if co.Node == (NODE{}) {
		return nil, errors.New("load config fail")
	}
	return &co, nil
}

func (obj *SYNC) DoSync() (SUMMARY, error) {
	object = obj
	node := object.Node
	connection := node.Connection
	path := node.Path
	parseIgnore(object.Ignore)
	if err := sync(connection.Host, connection.Port, connection.User, connection.Pass, path.Local, path.Remote); err != nil {
		return SUMMARY{}, err
	}
	return summary, nil
}

func (obj *SYNC) DoSyncCli() {
	object = obj
	isCli = true
	show := object.Cli
	node := object.Node
	connection := node.Connection
	path := node.Path
	parseIgnore(object.Ignore)
	log.Println(object)
	if err := sync(connection.Host, connection.Port, connection.User, connection.Pass, path.Local, path.Remote); err != nil {
		log.Fatalln(err)
	}
	fmt.Println("finished")
	if show.Unchange {
		fmt.Printf("-------------------- unchange(%d) --------------------\n", len(summary.unchange))
		for k, v := range summary.unchange {
			fmt.Printf("%d. %s\n", k, v)
		}
	}

	if show.Ignore {
		fmt.Printf("-------------------- ignore(%d) --------------------\n", len(summary.ignore))
		for k, v := range summary.ignore {
			fmt.Printf("%d. %s\n", k, v)
		}
	}

	if show.Change {
		fmt.Printf("-------------------- changefile(%d) --------------------\n", len(summary.change))
		for k, v := range summary.change {
			fmt.Printf("%d. %s\n", k, v)
		}
	}

	if show.Spendtime {
		fmt.Println("elapsed time: ", summary.spendtime)
	}
	log.Println("press ctr+c to exit")
	select {}
}

// Sync do sync from local to remote
func sync(host string, port int, userName, password, localPath, remotePath string) error {
	var (
		err        error
		sftpClient *sftp.Client
	)
	start := time.Now()
	sftpClient, err = connect(userName, password, host, port)
	if err != nil {
		return err
	}
	defer sftpClient.Close()

	if _, errStat := sftpClient.Stat(remotePath); errStat != nil {
		if os.IsNotExist(errStat) {
			if err = sftpClient.Mkdir(remotePath); err != nil {
				return fmt.Errorf("make dir fail:%s; error:%s", remotePath, err)

			}
		} else {
			return fmt.Errorf("sftpClient.Stat fail:%s; error:%s", remotePath, err)
		}
	}

	if _, err = ioutil.ReadDir(localPath); err != nil {
		return fmt.Errorf("read dir list fail:%s; error:%s", localPath, err)
	}

	if err = uploadDirectory(sftpClient, localPath, remotePath); err != nil {
		return err
	}
	elapsed := time.Since(start)
	summary.spendtime = elapsed
	return nil
}

// upload file
func uploadFile(sftpClient *sftp.Client, localFullName string, remoteFullName string) error {
	cli := object.Cli
	localFile, err := os.Open(localFullName)
	if err != nil {
		return fmt.Errorf("os.Open fail:%s; error:%s", localFullName, err)
	}
	defer localFile.Close()

	ll, err := ioutil.ReadAll(localFile)
	if err != nil {
		return fmt.Errorf("ReadAll fail:%s; error:%s", localFullName, err)
	}

	if _, err := sftpClient.Stat(remoteFullName); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("sftpClient.Stat fail:%s; error:%s", remoteFullName, err)
		}
	} else {
		// create will always return the same hash
		openFile, err := sftpClient.Open(remoteFullName)
		if err != nil {
			return fmt.Errorf("sftpClient.Open fail:%s; error:%s", remoteFullName, err)
		}
		defer openFile.Close()

		rr, err := ioutil.ReadAll(openFile)
		if err == nil && md5.Sum(rr) == md5.Sum(ll) {
			if isCli && cli.Print && cli.Unchange {
				log.Printf("file %s unchange ---- passed", localFullName)
			}
			summary.unchange = append(summary.unchange, localFullName)
			return nil
		}
	}
	remoteFile, err := sftpClient.Create(remoteFullName)
	if err != nil {
		return fmt.Errorf("sftpClient.Create fail:%s; error:%s", remoteFullName, err)
	}
	defer remoteFile.Close()

	remoteFile.Write(ll)
	if isCli && cli.Print && cli.Change {
		log.Printf("file %s upload ---- finished", localFullName)
	}
	summary.change = append(summary.change, localFullName)
	return nil
}

// upload directory
func uploadDirectory(sftpClient *sftp.Client, localPath string, remotePath string) error {
	cli := object.Cli
	no := object.Node
	localFiles, err := ioutil.ReadDir(localPath)
	if err != nil {
		return fmt.Errorf("read dir list fail:%s; error:%s", localPath, err)
	}

LABEL:
	for _, backupDir := range localFiles {
		localFullName := path.Join(localPath, backupDir.Name())
		remoteFullName := path.Join(remotePath, backupDir.Name())
		dir := strings.Replace(localFullName, no.Path.Local, "", -1)
		var push bool
		for _, f := range force {
			if match, _ := regexp.MatchString(f, dir); match {
				push = true
			}
		}
		if !push {
			for _, v := range ignore {
				if v.fix {
					if backupDir.Name() == v.file {
						summary.ignore = append(summary.ignore, localFullName)
						if isCli && cli.Print && cli.Ignore {
							log.Printf("file %s match in ignore ---- passed", localFullName)
						}
						continue LABEL
					}
				} else {
					reg := regexp.MustCompile(v.file)
					if reg.MatchString(dir) {
						summary.ignore = append(summary.ignore, localFullName)
						if isCli && cli.Print && cli.Ignore {
							log.Printf("file %s match in ignore ---- passed", localFullName)
						}
						continue LABEL
					}
				}
			}
		}
		if backupDir.IsDir() {
			if _, err = sftpClient.Stat(remoteFullName); os.IsNotExist(err) {
				if err = sftpClient.Mkdir(remoteFullName); err != nil {
					return fmt.Errorf("make dir fail:%s; error:%s", remoteFullName, err)
				}
			}
			if err = uploadDirectory(sftpClient, localFullName, remoteFullName); err != nil {
				return err
			}
		} else {
			if err = uploadFile(sftpClient, localFullName, remoteFullName); err != nil {
				return err
			}
		}
	}
	return nil
}

// connect
func connect(user, password, host string, port int) (*sftp.Client, error) {
	var (
		auth         []ssh.AuthMethod
		addr         string
		clientConfig *ssh.ClientConfig
		sshClient    *ssh.Client
		sftpClient   *sftp.Client
		err          error
	)
	// get auth method
	auth = make([]ssh.AuthMethod, 0)
	auth = append(auth, ssh.Password(password))

	clientConfig = &ssh.ClientConfig{
		User:            user,
		Auth:            auth,
		Timeout:         30 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //ssh.FixedHostKey(hostKey),
	}

	// connet to ssh
	addr = fmt.Sprintf("%s:%d", host, port)
	if sshClient, err = ssh.Dial("tcp", addr, clientConfig); err != nil {
		return nil, err
	}

	// create sftp client
	if sftpClient, err = sftp.NewClient(sshClient); err != nil {
		return nil, err
	}
	return sftpClient, nil
}

// parseIgnore
func parseIgnore(ign []string) {
	var push bool
	for _, rule := range ign {
		ig := IGNORE{}
		if strings.IndexAny(rule, "/*!") == -1 {
			ig.fix = true
		} else {
			rule = regexp.QuoteMeta(rule)
			if strings.Index(rule, "!") != -1 {
				push = true
				rule = strings.Replace(rule, "!", "", -1)
			}
			rule = strings.Replace(rule, "\\*", ".+", -1)
			if string(rule[0]) == "/" {
				rule = "^" + rule
			}
			if string(rule[len(rule)-1:]) != "/" {
				rule = rule + "$"
			}
		}
		if push {
			force = append(force, rule)
		} else {
			ig.file = rule
			ignore = append(ignore, ig)
		}
	}
}

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
)

// worked like `rinetd`.

var Logger logr.Logger

// forward TCP/UDP from ListenAddr to ToAddr
type chain struct {
	ListenAddr string
	Proto      string
	ToAddr     string
}

type encrypt struct {
	PriKey	string
	PubKey  string
	Proto   string
}

func (c *chain) String() string {
	return fmt.Sprintf("%v->%v/%v", c.ListenAddr, c.ToAddr, c.Proto)
}

// Keep udp session
type udpSession struct {
	FromCnn    net.PacketConn
	FromAddr   net.Addr
	OwnerChain *chain
	WriteTime  atomic.Value
	ToCnn      net.Conn
}

func (u *udpSession) Close() error {
	return u.ToCnn.Close()
}

type mgt struct {
	// 业务集合
	Encrypts     sync.Map
	Chains       []*chain
	UdpSsns      sync.Map // hash udpSession
	TcpCnnCnt    int64
	StatInterval time.Duration
	UdpSsnTTL    time.Duration
	WaitCtx      context.Context
	Wg           *sync.WaitGroup
}

func (m *mgt) UdpCnnCnt() uint64 {
	r := uint64(0)
	m.UdpSsns.Range(func(key, value interface{}) bool {
		r++
		return true
	})
	return r
}

func setupSignal(mgt0 *mgt, cancel context.CancelFunc) {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	signal.Notify(sigCh, syscall.SIGTERM)
	mgt0.Wg.Add(1)
	go func() {
		select {
		case <-sigCh:
			cancel()
		case <-mgt0.WaitCtx.Done():
		}
		mgt0.Wg.Done()
	}()

}

// 可以通过 WaitCtx.Done 关闭 Closer
// 可以通过 返回值 chan 关闭 Closer
func registerCloseCnn0(mgt0 *mgt, c io.Closer) chan bool {
	cc := make(chan bool, 1)
	mgt0.Wg.Add(1)
	go func() {
		select {
		case <-mgt0.WaitCtx.Done():
		case <-cc:
		}
		_ = c.Close()
		mgt0.Wg.Done()
	}()
	return cc
}

// 有的人是双向中任何一个方向断开，都会断开双向
// 代码这样写, 技巧：还使用到了 sync.Once 只运行 1 次。
// var once sync.Once
// go func() {
// 	io.Copy(connection, bashf)
// 	once.Do(close)
// }()
// go func() {
// 	io.Copy(bashf, connection)
// 	once.Do(close)
// }()
func forwardTCP(mgt0 *mgt, c *chain, left io.ReadWriteCloser, right io.ReadWriteCloser) {
	_ = c
	wg := new(sync.WaitGroup)
	bothClose := make(chan bool, 1)
	// right -> left
	mgt0.Wg.Add(1)
	wg.Add(1)
	go func() {
		b := make([]byte, 1024*1024)
		_, _ = io.CopyBuffer(left, right, b)
		wg.Done()
		mgt0.Wg.Done()
	}()

	// left -> right
	mgt0.Wg.Add(1)
	wg.Add(1)
	go func() {
		b := make([]byte, 1024*1024)
		_, _ = io.CopyBuffer(right, left, b)
		wg.Done()
		mgt0.Wg.Done()
	}()

	// wait read & write close
	mgt0.Wg.Add(1)
	go func() {
		wg.Wait()
		close(bothClose)
		mgt0.Wg.Done()
	}()

	select {
	case <-bothClose:
	case <-mgt0.WaitCtx.Done():
	}
	_ = left.Close()
	_ = right.Close()
}

func forwardTCPAES(mgt0 *mgt, c *chain, left io.ReadWriteCloser, right io.ReadWriteCloser) {
	_ = c
	wg := new(sync.WaitGroup)
	bothClose := make(chan bool, 1)
	// right -> left
	mgt0.Wg.Add(1)
	wg.Add(1)
	en,_ := mgt0.Encrypts.Load("aes")
	go func() {
		b := make([]byte, 1024*1024)
		_, _ = copyBuffer(left, right, b,[]byte(en.(*encrypt).PriKey),"r-l")
		wg.Done()
		mgt0.Wg.Done()
	}()

	// left -> right
	mgt0.Wg.Add(1)
	wg.Add(1)
	go func() {
		b := make([]byte, 1024*1024)
		_, _ = copyBuffer(right, left, b,[]byte(en.(*encrypt).PriKey),"l-r")
		wg.Done()
		mgt0.Wg.Done()
	}()

	// wait read & write close
	mgt0.Wg.Add(1)
	go func() {
		wg.Wait()
		close(bothClose)
		mgt0.Wg.Done()
	}()

	select {
	case <-bothClose:
	case <-mgt0.WaitCtx.Done():
	}
	_ = left.Close()
	_ = right.Close()
}

func copyBuffer(dst io.Writer, src io.Reader, buf []byte, aesKey []byte ,mark string) (written int64, err error) {
	logger := Logger.WithValues("algorithm","AES")
	if buf != nil && len(buf) == 0 {
		panic("empty buffer in copyBuffer")
	}
	// If the reader has a WriteTo method, use it to do the copy.
	// Avoids an allocation and a copy.
	//if wt, ok := src.(io.WriterTo); ok {
	//	return wt.WriteTo(dst)
	//}
	//// Similarly, if the writer has a ReadFrom method, use it to do the copy.
	//if rt, ok := dst.(io.ReaderFrom); ok {
	//	return rt.ReadFrom(src)
	//}
	if buf == nil {
		size := 32 * 1024
		if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
			if l.N < 1 {
				size = 1
			} else {
				size = int(l.N)
			}
		}
		buf = make([]byte, size)
	}
	for {
		nr, er := src.Read(buf)
		tStr := string(buf[0:nr])
		logger.Info("receive","message",tStr,"error",err,"mark",mark)
		var eLast string = ""
		if strings.Index(tStr,"e__") >= 0 {
			encrypted, _ := base64.StdEncoding.DecodeString(tStr[3:])
			origin, err := AesDecrypt([]byte(encrypted),aesKey)
			if err != nil {
				logger.Error(err, "error AesDecrypt")
			}
			eLast = string(origin)
		}else {
			encrypted, err := AesEncrypt(buf[0:nr],aesKey)
			if err != nil {
				logger.Error(err, "error AesEncrypt")
			}
			eLast = "e__" + base64.StdEncoding.EncodeToString(encrypted)
		}
		logger.Info("send","message",eLast,"mark",mark)
		if nr > 0 {
			//nw, ew := dst.Write(buf[0:nr])
			nw, ew := dst.Write([]byte(eLast))
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func udpSsnCanAge(us *udpSession, ttl time.Duration) bool {
	now := time.Now()
	whenWriteVoid := us.WriteTime.Load()
	if whenWriteVoid == nil {
		return true
	}
	whenWrite := whenWriteVoid.(time.Time)
	return now.After(whenWrite) && now.Sub(whenWrite) > ttl
}

// 只转发 right -> left 方向的 UDP 报文
// SetReadDeadline 协助完成老化功能
func forwardUDP(mgt0 *mgt, us *udpSession) {
	logger := Logger.WithValues("method","forwardUDP")
	logger = logger.WithValues("chain", us.OwnerChain.String())
	logger = logger.WithValues("fromAddr", us.FromAddr.String())
	logger.Info("enter")
	b := make([]byte, 64*1024)
	closeChan := registerCloseCnn0(mgt0, us)
	for {
		// add one more second to make sure sub time > ttl
		t := time.Now().Add(mgt0.UdpSsnTTL).Add(time.Second)
		_ = us.ToCnn.SetReadDeadline(t)
		// this is a udp read
		n, err := us.ToCnn.Read(b)
		_ = us.ToCnn.SetReadDeadline(time.Time{})
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				if udpSsnCanAge(us, mgt0.UdpSsnTTL) {
					logger.Info("read timeout and aged")
					break
				}
			} else if errors.Is(err, syscall.ECONNREFUSED) {
				// If peer not UDP listen, then we will recv ICMP
				// golang will give error net.OpError ECONNREFUSED
				// we ignore this error
				continue
			} else {
				logger.Error(err, "error read")
				break
			}
		} else {
			_, err = us.FromCnn.WriteTo(b[:n], us.FromAddr)
			if err != nil {
				logger.Error(err, "error WriteTo")
				break
			}
		}
	}
	close(closeChan)
	logger.Info("leave")
}

func setupTCPChain(mgt0 *mgt, c *chain) {
	var err error
	logger := Logger.WithValues("method","setupTCPChain")
	logger = logger.WithValues("chain", c.String())
	logger.Info("enter")
	defer logger.Info("leave")

	var lc net.ListenConfig
	sn, err := lc.Listen(mgt0.WaitCtx, c.Proto, c.ListenAddr)
	if err != nil {
		logger.Error(err, "error listen")
		return
	}
	closeChan := registerCloseCnn0(mgt0, sn)
	for {
		cnn, err := sn.Accept()
		if err != nil {
			logger.Error(err, "error accept")
			break
		}

		// connect peer
		d := new(net.Dialer)
		toCnn, err := d.DialContext(mgt0.WaitCtx, c.Proto, c.ToAddr)
		if err != nil {
			logger.Error(err, "error dial ToAddr")
			continue
		}
		logger.Info("new connection pair",
			"1From", cnn.RemoteAddr().String(), "1To", cnn.LocalAddr().String(),
			"2From", toCnn.LocalAddr().String(), "2To", toCnn.RemoteAddr().String())
		mgt0.Wg.Add(1)
		go func(arg0 *mgt, arg1 *chain, arg2 io.ReadWriteCloser, arg3 io.ReadWriteCloser) {
			atomic.AddInt64(&mgt0.TcpCnnCnt, 1)
			forwardTCP(arg0, arg1, arg2, arg3)
			atomic.AddInt64(&mgt0.TcpCnnCnt, -1)
			arg0.Wg.Done()
		}(mgt0, c, cnn, toCnn)

	}
	close(closeChan)
}

func setupAESChain(mgt0 *mgt, c *chain) {
	var err error
	logger := Logger.WithValues("method","setupAESChain")
	logger = logger.WithValues("chain", c.String())
	logger.Info("enter")
	defer logger.Info("leave")

	c.Proto = "tcp"

	var lc net.ListenConfig
	sn, err := lc.Listen(mgt0.WaitCtx, c.Proto, c.ListenAddr)
	if err != nil {
		logger.Error(err, "error listen")
		return
	}
	closeChan := registerCloseCnn0(mgt0, sn)
	for {
		cnn, err := sn.Accept()
		if err != nil {
			logger.Error(err, "error accept")
			break
		}

		// connect peer
		d := new(net.Dialer)
		toCnn, err := d.DialContext(mgt0.WaitCtx, c.Proto, c.ToAddr)
		if err != nil {
			logger.Error(err, "error dial ToAddr")
			continue
		}
		logger.Info("new coin connection pair",
			"1From", cnn.RemoteAddr().String(), "1To", cnn.LocalAddr().String(),
			"2From", toCnn.LocalAddr().String(), "2To", toCnn.RemoteAddr().String())
		mgt0.Wg.Add(1)
		go func(arg0 *mgt, arg1 *chain, arg2 io.ReadWriteCloser, arg3 io.ReadWriteCloser) {
			atomic.AddInt64(&mgt0.TcpCnnCnt, 1)
			forwardTCPAES(arg0, arg1, arg2, arg3)
			atomic.AddInt64(&mgt0.TcpCnnCnt, -1)
			arg0.Wg.Done()
		}(mgt0, c, cnn, toCnn)

	}
	close(closeChan)
}

func newUdpSsn(mgt0 *mgt, c *chain, fromAddr net.Addr,
	fromCnn net.PacketConn, logger logr.Logger) *udpSession {
	d := new(net.Dialer)
	toCnn, err := d.DialContext(mgt0.WaitCtx, c.Proto, c.ToAddr)
	if err != nil {
		logger.Error(err, "error dial ToAddr")
		return nil
	}
	u := &udpSession{}
	u.WriteTime.Store(time.Now())
	u.ToCnn = toCnn
	u.FromAddr = fromAddr
	u.FromCnn = fromCnn
	u.OwnerChain = c
	return u
}

func setupUDPChain(mgt0 *mgt, c *chain) {
	var err error
	logger := Logger.WithValues("method","setupUDPChain")
	logger = logger.WithValues("chain", c.String())
	logger.Info("enter")
	defer logger.Info("leave")

	var lc net.ListenConfig
	pktCnn, err := lc.ListenPacket(mgt0.WaitCtx, c.Proto, c.ListenAddr)
	if err != nil {
		logger.Error(err, "error ListenPacket")
		return
	}
	closeChan := registerCloseCnn0(mgt0, pktCnn)
	rbuf := make([]byte, 128*1024)
	for {
		rsize, raddr, err := pktCnn.ReadFrom(rbuf)
		if err != nil {
			logger.Error(err, "error ReadFrom")
			break
		}
		var oldUdpSsn *udpSession
		newUdpSsn := newUdpSsn(mgt0, c, raddr, pktCnn, logger)
		ssnKey := raddr.String()
		ssn, ok := mgt0.UdpSsns.Load(ssnKey)
		if !ok {
			if newUdpSsn == nil {
				logger.Error(fmt.Errorf("none of valid Udp Session"),
					"cannot found old udpSession and cannot setup udpSession")
				continue
			}
			mgt0.UdpSsns.Store(ssnKey, newUdpSsn)
			oldUdpSsn = newUdpSsn
			logger.Info("new connection pair",
				"1From", raddr.String(), "1To", pktCnn.LocalAddr().String(),
				"2From", newUdpSsn.ToCnn.LocalAddr().String(), "2To", newUdpSsn.ToCnn.RemoteAddr().String())
			mgt0.Wg.Add(1)
			go func(arg0 *mgt, arg1 *udpSession) {
				forwardUDP(arg0, arg1)
				mgt0.UdpSsns.Delete(ssnKey)
				arg0.Wg.Done()
			}(mgt0, newUdpSsn)
		} else {
			oldUdpSsn = ssn.(*udpSession)
		}
		_, err = oldUdpSsn.ToCnn.Write(rbuf[:rsize])
		oldUdpSsn.WriteTime.Store(time.Now())
		if err != nil {
			logger.Error(err, "error 2WriteTo")
			_ = oldUdpSsn.Close()
			mgt0.UdpSsns.Delete(ssnKey)
		}
	}
	close(closeChan)
}

/**
放弃的一种配置文件格式
rinetd.toml sample
[[Chans]]
ListenAddr="0.0.0.0:5678"
Proto="tcp"
PeerAddr="127.0.0.1:8100"

[[Chans]]
ListenAddr="0.0.0.0:5679"
Proto="tcp"
PeerAddr="127.0.0.1:8200"

parser sample
0.0.0.0 5678/tcp 127.0.0.1 8100/tcp

用上面的都太复杂了
*/

func setupChains(mgt0 *mgt, cancel context.CancelFunc) {
	setupSignal(mgt0, cancel)
	if len(mgt0.Chains) == 0 {
		Logger.Info("no chains to work")
		cancel()
		return
	}
	for _, c := range mgt0.Chains {
		mgt0.Wg.Add(1)
		go func(arg0 *mgt, arg1 *chain) {
			if arg1.Proto == "tcp" {
				setupTCPChain(arg0, arg1)
			} else if arg1.Proto == "udp" {
				setupUDPChain(arg0, arg1)
			} else if arg1.Proto == "tcp_encrypt_aes" {
				setupAESChain(arg0, arg1)
			}
			arg0.Wg.Done()
		}(mgt0, c)
	}
}

func listChainsFromConf(filename string, mgt0 *mgt) {
	fr, err := os.Open(filename)
	if err != nil {
		Logger.Error(err, "error openfile", "filename", filename)
		return
	}

	sc := bufio.NewScanner(fr)
	for sc.Scan() {
		t := sc.Text()
		t = strings.TrimSpace(t)
		if len(t) <= 0 || strings.HasPrefix(t, "#") || strings.HasPrefix(t, "//") {
			continue
		}

		ar := strings.Fields(t)
		if len(ar) < 3 {
			continue
		}
		arValid := make([]string, 0)
		for _, e := range ar {
			e = strings.TrimSpace(e)
			if len(e) > 0 {
				arValid = append(arValid, strings.ToLower(e))
			}
		}
		if len(arValid) == 3 {
			if arValid[0] == "aes" {
				e := &encrypt{}
				e.Proto = arValid[0]
				e.PriKey = arValid[1]
				e.PubKey = arValid[2]
				mgt0.Encrypts.Store(e.Proto,e)
			}else {
				v := &chain{}
				v.ListenAddr = arValid[0]
				v.ToAddr = arValid[1]
				v.Proto = arValid[2]
				mgt0.Chains = append(mgt0.Chains, v)
			}
		}
	}
	mgt0.Encrypts.LoadOrStore("aes",&encrypt{Proto: "aes",PriKey: "zHvL%$o0oNbxXZnk#o2qbqCeQB1iXeIR"})
	_ = fr.Close()
}

func stat(mgt0 *mgt) {
	tc := time.Tick(mgt0.StatInterval)
	logger := Logger.WithValues("method","stat")
loop:
	for {
		select {
		case <-mgt0.WaitCtx.Done():
			break loop
		case <-tc:
			logger.Info("stat count", "tcp", mgt0.TcpCnnCnt, "udp", mgt0.UdpCnnCnt())
		}
	}
}

func doWork() {
	var err error
	var cancel context.CancelFunc
	mgt0 := new(mgt)
	mgt0.Wg = new(sync.WaitGroup)
	mgt0.Chains = make([]*chain, 0)
	mgt0.StatInterval = time.Minute
	mgt0.UdpSsnTTL = time.Minute
	mgt0.WaitCtx, cancel = context.WithCancel(context.Background())

	fullPath, _ := os.Executable()
	cur := filepath.Dir(fullPath)
	confPath := filepath.Join(cur, "zredirector.conf")
	_, err = os.Stat(confPath)
	if err != nil {
		Logger.Error(err, "error config file, not exists", "filepath", confPath)
		return
	}
	listChainsFromConf(confPath, mgt0)
	// create mgt0.WaitCtx
	setupChains(mgt0, cancel)
	stat(mgt0)
	Logger.Info("all work exit")
	mgt0.Wg.Wait()
}


// ######encrypt toolkit###AES#######

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

//AES加密,CBC
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = PKCS7Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))
	blockMode.CryptBlocks(crypted, origData)
	return crypted, nil
}

//AES解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS7UnPadding(origData)
	return origData, nil
}

func NewStdoutLogger() logr.Logger {
	return funcr.New(func(prefix, args string) {
		if prefix != "" {
			_ = fmt.Sprintf("%s: %s\n", prefix, args)
		} else {
			fmt.Println(args)
		}
	}, funcr.Options{})
}

func main() {
	Logger = NewStdoutLogger()
	Logger = Logger.WithValues("pid", os.Getpid())
	doWork()
	Logger.Info("main exit")
}

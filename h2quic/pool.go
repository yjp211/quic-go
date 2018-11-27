package h2quic

import (
	"errors"
	"sync"
	"time"
	"io"
	"sync/atomic"
)

var (
	ErrTimeout = errors.New("timeout")
	ErrBusy = errors.New("busy")
	ErrShutdown = errors.New("shutdown")
)

type ProxyConn interface {
	io.Closer
	IsActive() bool // conn is still active
}


type Factory func(addr string, timeout time.Duration, tripper *RoundTripper) (ProxyConn, error)

type ProxyPool struct {
	addr string
	timeout time.Duration
	maxConn int //max connect for each syringe server

	connChain chan ProxyConn // like as [conn1,conn2]
	counter int32 //current open
	closed  bool

	factory Factory
	tripper *RoundTripper

	sync.Mutex

}

func NewProxyPool(addr string, timeout time.Duration,  maxConn int, factory Factory, tripper *RoundTripper) *ProxyPool {
	return &ProxyPool{
		addr: addr,
		timeout: timeout,
		maxConn: maxConn,

		connChain : make(chan ProxyConn, maxConn),
		counter: 0,
		closed: false,

		factory: factory,
		tripper: tripper,
	}
}



func (p *ProxyPool) Get(trywait bool) (ProxyConn, error) {
	if p.closed {
		return nil, ErrShutdown
	}

	loop := true
	for loop {
		select {
		case conn, ok := <-p.connChain:
			if ok {
				if conn.IsActive() {
					return conn, nil
				}else{
					conn.Close()
					atomic.AddInt32(&p.counter, -1)
					continue
				}
			} else {
				return nil, ErrShutdown
			}
		default:
			 loop = false
			 break
		}
	}

	if  int(p.counter) >= p.maxConn {
		if trywait {
			for {
				select {
				case conn, ok := <-p.connChain:
					if ok {
						if conn.IsActive() {
							return conn, nil
						}else{
							conn.Close()
							atomic.AddInt32(&p.counter, -1)
							continue
						}
					} else {
						return nil, ErrShutdown
					}
				case <-time.After(p.timeout):
					return nil, ErrTimeout
				}
			}
		}else{
			return nil, ErrBusy
		}
	}else{
		conn, err := p.factory(p.addr, p.timeout, p.tripper)
		if err != nil {
			return nil, err
		}
		atomic.AddInt32(&p.counter, 1)
		return conn, nil
	}
}


func (p *ProxyPool) Release(conn ProxyConn) error {
	p.Lock()
	defer p.Unlock()

	if p.closed {
		conn.Close()
		return ErrShutdown
	}

	if  !conn.IsActive() || int(p.counter) > p.maxConn {
		conn.Close()
		atomic.AddInt32(&p.counter, -1)
	}else{
		p.connChain <- conn
	}
	return nil
}

func (p *ProxyPool) Shutdown() error {
	p.Lock()
	defer p.Unlock()

	if p.closed {
		return ErrShutdown
	}

	close(p.connChain)
	for conn := range p.connChain {
		conn.Close()
	}
	p.closed = true
	return nil
}
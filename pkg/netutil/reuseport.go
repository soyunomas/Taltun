package netutil

import (
	"context"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// ListenUDPReusePort crea un UDPConn con las flags SO_REUSEPORT y SO_REUSEADDR activadas.
// Esto permite lanzar múltiples listeners en el mismo puerto y que el Kernel distribuya la carga.
func ListenUDPReusePort(network, address string) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Activar SO_REUSEPORT
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if opErr != nil {
					return
				}
				// Activar SO_REUSEADDR (buena práctica para reiniciar rápido)
				opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	conn, err := lc.ListenPacket(context.Background(), network, address)
	if err != nil {
		return nil, err
	}

	return conn.(*net.UDPConn), nil
}

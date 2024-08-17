package socket

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/nlpodyssey/gopickle/pickle"
)

const (
	commandTerminator    = "<F2B_END_COMMAND>"
	pingCommand          = "ping"
	statusCommand        = "status"
	versionCommand       = "version"
	banTimeCommandFmt    = "get %s bantime"
	findTimeCommandFmt   = "get %s findtime"
	maxRetriesCommandFmt = "get %s maxretry"
	bannedCommand        = "banned"
	socketReadBufferSize = 1024
)

func (s *Fail2BanSocket) sendCommand(command []string) (interface{}, error) {
	err := s.write(command)
	if err != nil {
		return nil, err
	}
	return s.read()
}

func (s *Fail2BanSocket) write(command []string) error {
	err := s.encoder.Encode(command)
	if err != nil {
		return err
	}
	_, err = s.socket.Write([]byte(commandTerminator))
	if err != nil {
		return err
	}
	return nil
}

func (s *Fail2BanSocket) read() (interface{}, error) {
	reader := bufio.NewReader(s.socket)

	data := []byte{}
	for {
		buf := make([]byte, socketReadBufferSize)
		_, err := reader.Read(buf)
		if err != nil {
			return nil, err
		}
		data = append(data, buf...)
		containsTerminator := bytes.Contains(data, []byte(commandTerminator))
		if containsTerminator {
			break
		}
	}

	bufReader := bytes.NewReader(data)
	unpickler := pickle.NewUnpickler(bufReader)

	unpickler.FindClass = func(module, name string) (interface{}, error) {
		if (module == "builtins" || module == "__builtin__") && name == "str" {
			return &Py_builtins_str{}, nil
		}
		return nil, fmt.Errorf("class not found: " + module + " : " + name)
	}

	return unpickler.Load()
}

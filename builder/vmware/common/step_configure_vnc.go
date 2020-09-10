package common

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/packer/common/net"
	"github.com/hashicorp/packer/helper/multistep"
	"github.com/hashicorp/packer/packer"
	"github.com/vmware/govmomi/vim25/types"
	"log"
	"math/rand"
	"net/http"
)

// This step configures the VM to enable the VNC server.
//
// Uses:
//   ui     packer.Ui
//   vmx_path string
//
// Produces:
//   vnc_port int - The port that VNC is configured to listen on.
type StepConfigureVNC struct {
	Enabled            bool
	VNCBindAddress     string
	VNCPortMin         int
	VNCPortMax         int
	VNCDisablePassword bool
	DriverConfig       *DriverConfig
	VNCOverWebsocket   bool

	l *net.Listener
}

type VNCAddressFinder interface {
	VNCAddress(context.Context, string, int, int) (string, int, error)

	// UpdateVMX, sets driver specific VNC values to VMX data.
	UpdateVMX(vncAddress, vncPassword string, vncPort int, vmxData map[string]string)
}

func (s *StepConfigureVNC) VNCAddress(ctx context.Context, vncBindAddress string, portMin, portMax int) (string, int, error) {
	var err error
	s.l, err = net.ListenRangeConfig{
		Addr:    s.VNCBindAddress,
		Min:     s.VNCPortMin,
		Max:     s.VNCPortMax,
		Network: "tcp",
	}.Listen(ctx)
	if err != nil {
		return "", 0, err
	}

	s.l.Listener.Close() // free port, but don't unlock lock file
	return s.l.Address, s.l.Port, nil
}

func VNCPassword(skipPassword bool) string {
	if skipPassword {
		return ""
	}
	length := int(8)

	charSet := []byte("012345689abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	charSetLength := len(charSet)

	password := make([]byte, length)

	for i := 0; i < length; i++ {
		password[i] = charSet[rand.Intn(charSetLength)]
	}

	return string(password)
}

func (s *StepConfigureVNC) Run(ctx context.Context, state multistep.StateBag) multistep.StepAction {
	if !s.Enabled {
		log.Println("Skipping VNC configuration step...")
		return multistep.ActionContinue
	}
	ui := state.Get("ui").(packer.Ui)

	if s.VNCOverWebsocket {
		driver := state.Get("driver").(*ESX5Driver)

		// Aquire websocket ticket
		log.Printf("[DEBUG] Acquiring VNC over websocket ticket")
		ticket, err := driver.AcquireTicket()
		if err != nil {
			err := fmt.Errorf("Error reading VMX file: %s", err)
			state.Put("error", err)
			ui.Error(err.Error())
			return multistep.ActionHalt
		}
		host := ticket.Host
		if len(host) == 0 {
			host = s.DriverConfig.RemoteHost
		}
		port := ticket.Port
		if port == 0 {
			port = 443
		}

		log.Printf("[DEBUG] Dialing websocket")
		dialer := &websocket.Dialer{
			Proxy:           http.ProxyFromEnvironment,
			Subprotocols:    []string{"uint8utf8", "binary", "vmware-vvc", "wmks"},
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		url := fmt.Sprintf("wss://%s:%d/ticket/%s", host, port, ticket.Ticket)
		dial, _, err := dialer.Dial(url, nil)
		if err != nil {
			state.Put("error", err)
			ui.Error(err.Error())
			return multistep.ActionHalt
		}
		conn := &ConnWrapper{dial, ticket}
		err = conn.handshake(state)
		if err != nil {
			state.Put("error", err)
			ui.Error(err.Error())
			return multistep.ActionHalt
		}

		state.Put("vnc_conn", conn)
		return multistep.ActionContinue
	}

	driver := state.Get("driver").(Driver)
	vmxPath := state.Get("vmx_path").(string)
	vmxData, err := ReadVMX(vmxPath)
	if err != nil {
		err := fmt.Errorf("Error reading VMX file: %s", err)
		state.Put("error", err)
		ui.Error(err.Error())
		return multistep.ActionHalt
	}

	var vncFinder VNCAddressFinder
	if finder, ok := driver.(VNCAddressFinder); ok {
		vncFinder = finder
	} else {
		vncFinder = s
	}

	log.Printf("Looking for available port between %d and %d", s.VNCPortMin, s.VNCPortMax)
	vncBindAddress, vncPort, err := vncFinder.VNCAddress(ctx, s.VNCBindAddress, s.VNCPortMin, s.VNCPortMax)

	if err != nil {
		state.Put("error", err)
		ui.Error(err.Error())
		return multistep.ActionHalt
	}

	vncPassword := VNCPassword(s.VNCDisablePassword)

	log.Printf("Found available VNC port: %s:%d", vncBindAddress, vncPort)

	vncFinder.UpdateVMX(vncBindAddress, vncPassword, vncPort, vmxData)

	if err := WriteVMX(vmxPath, vmxData); err != nil {
		err := fmt.Errorf("Error writing VMX data: %s", err)
		state.Put("error", err)
		ui.Error(err.Error())
		return multistep.ActionHalt
	}

	state.Put("vnc_port", vncPort)
	state.Put("vnc_ip", vncBindAddress)
	state.Put("vnc_password", vncPassword)

	return multistep.ActionContinue
}

func (*StepConfigureVNC) UpdateVMX(address, password string, port int, data map[string]string) {
	data["remotedisplay.vnc.enabled"] = "TRUE"
	data["remotedisplay.vnc.port"] = fmt.Sprintf("%d", port)
	data["remotedisplay.vnc.ip"] = address
	if len(password) > 0 {
		data["remotedisplay.vnc.password"] = password
	}
}

func (s *StepConfigureVNC) Cleanup(multistep.StateBag) {
	if s.l != nil {
		if err := s.l.Close(); err != nil {
			log.Printf("failed to unlock port lockfile: %v", err)
		}
	}
}

type ConnWrapper struct {
	c      *websocket.Conn
	ticket *types.VirtualMachineTicket
}

// KeyEvent indiciates a key press or release and sends it to the server.
// The key is indicated using the X Window System "keysym" value. Use
// Google to find a reference of these values. To simulate a key press,
// you must send a key with both a down event, and a non-down event.
//
// See 7.5.4.
func (c *ConnWrapper) KeyEvent(keysym uint32, down bool) error {
	var downFlag uint8 = 0
	if down {
		downFlag = 1
	}

	data := []interface{}{
		uint8(4),
		downFlag,
		uint8(0),
		uint8(0),
		keysym,
	}

	for _, val := range data {
		buf := new(bytes.Buffer)
		err := binary.Write(buf, binary.LittleEndian, val)
		if err != nil {
			fmt.Println("binary.Write failed:", err)
		}
		if err := c.c.WriteMessage(websocket.BinaryMessage, buf.Bytes()); err != nil {
			log.Printf("MOSS failed to send %#v", val)
			return err
		}
	}

	log.Printf("[DEBUG] reading back %#v", keysym)
	_, _, err := c.c.ReadMessage()
	if err != nil {
		return fmt.Errorf("Error %#v: %s", keysym, err)
	}

	return nil
}

func (c *ConnWrapper) Close() error {
	return c.c.Close()
}

func (c *ConnWrapper) handshake(state multistep.StateBag) error {
	pauseFn := state.Get("pauseFn").(multistep.DebugPauseFn)
	log.Printf("[DEBUG] VNC over websocket handshake")

	// --------
	log.Printf("[DEBUG] Reading Protocol Version")
	_, protocolVersion, err := c.c.ReadMessage()
	if err != nil {
		return fmt.Errorf("Error reading protocol version: %s", err)
	}
	log.Printf("[DEBUG] VNC Server Protocol Version %s", string(protocolVersion))

	pauseFn(multistep.DebugLocationAfterRun,
		fmt.Sprintf("reading protocol version"), state)
	// --------

	// --------
	log.Printf("[DEBUG] Sending back the Protocol Version")
	err = c.c.WriteMessage(websocket.BinaryMessage, protocolVersion)
	if err != nil {
		return fmt.Errorf("Error sending protocol version: %s", err)
	}

	pauseFn(multistep.DebugLocationAfterRun,
		fmt.Sprintf("sending protocol version"), state)
	// --------

	// --------
	log.Printf("[DEBUG] Reading something")
	_, something, err := c.c.ReadMessage()
	if err != nil {
		return fmt.Errorf("Error reading something: %s", err)
	}
	log.Printf("[DEBUG] something %s", string(something))

	pauseFn(multistep.DebugLocationAfterRun,
		fmt.Sprintf("reading something"), state)
	// --------

	// --------
	log.Printf("[DEBUG] Sending something")
	buf := new(bytes.Buffer)
	err = binary.Write(buf, binary.LittleEndian, uint8(1)) // none auth
	if err != nil {
		fmt.Println("binary.Write failed:", err)
	}
	if err := c.c.WriteMessage(websocket.BinaryMessage, buf.Bytes()); err != nil {
		return fmt.Errorf("Error something: %s", err)
	}

	pauseFn(multistep.DebugLocationAfterRun,
		fmt.Sprintf("sending something"), state)
	// --------

	// --------
	log.Printf("[DEBUG] Reading something")
	_, something, err = c.c.ReadMessage()
	if err != nil {
		return fmt.Errorf("Error reading something: %s", err)
	}
	log.Printf("[DEBUG] something %s", string(something))

	pauseFn(multistep.DebugLocationAfterRun,
		fmt.Sprintf("reading something"), state)
	// --------

	// --------
	log.Printf("[DEBUG] Sending something")
	if err := c.c.WriteMessage(websocket.BinaryMessage, buf.Bytes()); err != nil {
		return fmt.Errorf("Error sending something: %s", err)
	}

	pauseFn(multistep.DebugLocationAfterRun,
		fmt.Sprintf("sending something"), state)
	// --------

	// --------
	log.Printf("[DEBUG] Reading something")
	_, something, err = c.c.ReadMessage()
	if err != nil {
		return fmt.Errorf("Error reading something: %s", err)
	}
	log.Printf("[DEBUG] something %s", string(something))

	pauseFn(multistep.DebugLocationAfterRun,
		fmt.Sprintf("reading something"), state)
	// --------

	return nil
}

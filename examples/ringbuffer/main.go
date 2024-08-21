//go:build linux

package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const qdiscClsact = "clsact"
const MAX_DNS_NAME_LENGTH = 256

type DNSQuery struct {
	RecordType uint16
	Class      uint16
	Name       [MAX_DNS_NAME_LENGTH]byte
}
type InAddr struct {
	Addr [4]byte
}
type DNSServer struct {
	IPAddr InAddr
	Port   uint16
	// 2 bytes padding
	Padding [2]byte
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-14 bpf ringbuffer.c -- -I /usr/include/x86_64-linux-gnu/ -I../headers
func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifName := os.Args[1]
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	removeTCFilters(iface.Name, netlink.HANDLE_MIN_INGRESS)
	removeTCFilters(iface.Name, netlink.HANDLE_MIN_EGRESS)
	defer func() {
		log.Printf("Removing TC filters at exit")
		removeTCFilters(iface.Name, netlink.HANDLE_MIN_INGRESS)
		removeTCFilters(iface.Name, netlink.HANDLE_MIN_EGRESS)
	}()

	link, err := netlink.LinkByName(ifName)
	if err != nil {
		log.Fatalf("getting interface %s by name: %w", ifName, err)
	}

	// Attach the program to INGRESS TC.
	err = attachTCProgram(link, objs.IngressProgFunc, "ingress", netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		log.Fatalf("could not attach ingress TC program: %s", err)
	}
	// Attach the program to EGRESS TC.
	err = attachTCProgram(link, objs.EgressProgFunc, "egress", netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		log.Fatalf("could not attach egress TC program: %s", err)
	}

	redir_config_map := objs.QueryRedirectionConfig

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start a goroutine to handle user input
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("Enter a hostname (or Ctrl+C to exit): ")
			if scanner.Scan() {
				hostname := scanner.Text()

				// Update the hostname in the BPF map
				q := DNSQuery{
					Name: [256]byte{},
				}
				copy(q.Name[:], []byte(hostname))

				v := DNSServer{
					IPAddr: InAddr{
						Addr: [4]byte{127, 0, 0, 1},
					},
					Port: 53,
				}

				if err := redir_config_map.Put(&q, &v); err != nil {
					log.Fatalf("failed to insert into map: %s", err)
				}

				log.Printf("Inserted hostname %s into the map", hostname)

				v2 := DNSServer{}
				redir_config_map.Lookup(&q, &v2)
				log.Printf("IPAddr: %d.%d.%d.%d\n", v2.IPAddr.Addr[0], v2.IPAddr.Addr[1], v2.IPAddr.Addr[2], v2.IPAddr.Addr[3])
			}
		}
	}()

	// Block until a signal is received
	sig := <-sigChan
	fmt.Println("Received signal:", sig)

	// Cleanup or shutdown tasks
	fmt.Println("Shutting down gracefully...")

}

// attachTCProgram attaches the TC program 'prog' to link.
func attachTCProgram(link netlink.Link, prog *ebpf.Program, progName string, qdiscParent uint32) error {
	if prog == nil {
		return errors.New("cannot attach a nil program")
	}

	if err := replaceQdisc(link); err != nil {
		return fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    qdiscParent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			//Priority:  option.Config.TCFilterPriority,
			Priority: 100,
		},
		Fd:           prog.FD(),
		Name:         fmt.Sprintf("%s-%s", progName, link.Attrs().Name),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("replacing tc filter: %w", err)
	}

	return nil
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  qdiscClsact,
	}

	return netlink.QdiscReplace(qdisc)
}

// removeTCFilters removes all tc filters from the given interface.
// Direction is passed as netlink.HANDLE_MIN_{INGRESS,INGRESS} via tcDir.
func removeTCFilters(ifName string, tcDir uint32) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return err
	}

	filters, err := netlink.FilterList(link, tcDir)
	if err != nil {
		return err
	}

	for _, f := range filters {
		if err := netlink.FilterDel(f); err != nil {
			return err
		}
	}

	return nil
}
